#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import os
import re
import sys
import time
import struct
import bisect

import json
import argparse

from builtins import range

#////////////////////////////////////////////////////////////////////////////////////////////

try:
    import idaapi
except:
    idaapi = None

radare2 = True if 'R2PIPE_IN' in os.environ else False

args = None

#////////////////////////////////////////////////////////////////////////////////////////////


#//////PRINTING BEGIN//////
log_file = sys.stderr
sym_file = sys.stdout

def print_log(*args):
    global log_file

    if log_file is None:
        return
    print("".join(map(str,args)), file=log_file)

def print_sym(*args):
    global sym_file

    if sym_file is None:
        return
    print("".join(map(str,args)), file=sym_file)
#//////PRINTING END//////

#//////SIMENG_MIASM BEGIN//////
miasm_installed = True

try:
    from miasm.core.utils import decode_hex
    from miasm.analysis.machine import Machine
    from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, \
        EXCEPT_BREAKPOINT_MEMORY, EXCEPT_ACCESS_VIOL
except ImportError:
    miasm_installed = False

g_machine = None
g_code_size = 0
g_jitter = None
g_cpu = None

g_mem_access = {}

g_gki_kernel = 0

# Handler
def mem_breakpoint_handler(jitter):
    print_log("======")
    print_log("Data access caught!")

    mem_r = jitter.vm.get_memory_read()
    if len(mem_r) > 0:
        for s, e in mem_r:
            print_log("%s - %s" % (hex(s), hex(e - s)))
            g_mem_access[jitter.pc] = {}
            g_mem_access[jitter.pc]['dir'] = 'read'
            g_mem_access[jitter.pc]['addr'] = s
            g_mem_access[jitter.pc]['len'] = e - s
    else:
        print_log("No read")

    mem_w = jitter.vm.get_memory_write()
    if len(mem_w) > 0:
        for s, e in mem_w:
            print_log("%s - %s" % (hex(s), hex(e - s)))
            g_mem_access[jitter.pc] = {}
            g_mem_access[jitter.pc]['dir'] = 'write'
            g_mem_access[jitter.pc]['addr'] = s
            g_mem_access[jitter.pc]['len'] = e - s
    else:
        print_log("No write")

    print_log("pc = %s" % (hex(jitter.cpu.PC)))
    print_log("[DBG] vm.exception = %d" % (jitter.vm.get_exception()))
    print_log("======")

    # Cleanup? shouldn't be necessary
    jitter.vm.set_exception(0)
    jitter.vm.reset_memory_access()

    return True


def miasm_load_vmlinux(kallsyms, vmlinux):
    global g_machine
    global g_code_size
    global g_jitter
    global g_cpu

    if kallsyms['arch'] == 'arm':
        g_cpu = "arml"
    elif kallsyms['arch'] == 'arm64':
        g_cpu = "aarch64l"
    else:
        raise Exception('Invalid arch')

    g_machine = Machine(g_cpu)
    g_jitter = g_machine.jitter('gcc')

    start_addr = kallsyms['_start']
    g_code_size = ((len(vmlinux) + 0x1000) >> 12 << 12)
    g_code_size += 0x8000000    # bss
    end_addr = start_addr + g_code_size
    print_log("[+]mapping %s - %s" % (hex(start_addr), hex(end_addr)))

    g_jitter.vm.add_memory_page(start_addr, PAGE_READ|PAGE_WRITE, b"\x00"*g_code_size, "code page")

    g_jitter.vm.set_mem(kallsyms['_start'], vmlinux)

    # stack
    g_jitter.vm.add_memory_page(0xdead1000, PAGE_READ|PAGE_WRITE, b"\x00"*0x2000, "stack")


def miasm_set_mem(addr, body):
    global g_machine
    global g_jitter

    assert(len(body) <= 4096)

    all_mem = g_jitter.vm.get_all_memory()
    is_mapped = False

    for start in all_mem.keys():
        # print_log("%s: %d" % (hex(addr), all_mem[addr]['size']))
        if addr >= start and addr < (start + all_mem[start]['size']):
            is_mapped = True
            break

    if not is_mapped:
        g_jitter.vm.add_memory_page(addr, PAGE_READ|PAGE_WRITE, b"\x00"*0x1000, "data")

    print_log('[+]set memory content @ %s' % (hex(addr)))
    g_jitter.vm.set_mem(addr, body)


def get_mem_access(kallsyms, sym_name, args):
    global g_machine
    global g_code_size
    global g_jitter
    global g_cpu
    global g_mem_access

    # Assuming the symbol is there
    sym_idx = kallsyms['name'].index(sym_name)
    sym_addr = kallsyms['address'][sym_idx]
    sym_size = kallsyms['address'][sym_idx + 1] - sym_addr
    if sym_size <= 0:
        raise Exception('Invalid address table?')

    # Parsing args
    if g_cpu == 'arml':
        for reg, value in args.items():
            if reg == 'R0':
                g_jitter.cpu.R0 = value
            elif reg == 'R1':
                g_jitter.cpu.R1 = value
            elif reg == 'R2':
                g_jitter.cpu.R2 = value
            elif reg == 'R3':
                g_jitter.cpu.R3 = value
            elif reg == 'R4':
                g_jitter.cpu.R4 = value
            elif reg == 'R5':
                g_jitter.cpu.R5 = value
            elif reg == 'R6':
                g_jitter.cpu.R6 = value
            elif reg == 'R7':
                g_jitter.cpu.R7 = value
            g_jitter.cpu.SP = 0xdead2000
    elif g_cpu == 'aarch64l':
        for reg, value in args.items():
            if reg == 'X0':
                g_jitter.cpu.X0 = value
            elif reg == 'X1':
                g_jitter.cpu.X1 = value
            elif reg == 'X2':
                g_jitter.cpu.X2 = value
            elif reg == 'X3':
                g_jitter.cpu.X3 = value
            elif reg == 'X4':
                g_jitter.cpu.X4 = value
            elif reg == 'X5':
                g_jitter.cpu.X5 = value
            elif reg == 'X6':
                g_jitter.cpu.X6 = value
            elif reg == 'X7':
                g_jitter.cpu.X7 = value
            g_jitter.cpu.SP = 0xdead2000
    else:
        raise Exception('Invalid arch')

    bp_start = kallsyms['_start']
    bp_size = g_code_size
    g_jitter.exceptions_handler.callbacks[EXCEPT_BREAKPOINT_MEMORY] = []
    g_jitter.add_exception_handler(EXCEPT_BREAKPOINT_MEMORY, mem_breakpoint_handler)
    print_log('[+]setting up memory breakpoint in range [%s, %s]' % (hex(bp_start), hex(bp_start + bp_size)))
    g_jitter.vm.add_memory_breakpoint(bp_start, bp_size, PAGE_READ | PAGE_WRITE)

    # g_jitter.set_trace_log()

    if g_cpu == 'arml':
        g_jitter.cpu.LR = 0xdead0000
    elif g_cpu == 'aarch64l':
        g_jitter.cpu.LR = 0xdead0000

    g_mem_access = {}

    g_jitter.init_run(sym_addr)
    try:
        g_jitter.continue_run()
    except AssertionError:
        assert g_jitter.vm.get_exception() == EXCEPT_ACCESS_VIOL

    g_jitter.vm.remove_memory_breakpoint(bp_start, PAGE_READ | PAGE_WRITE)

    for pc in g_mem_access.keys():
        access = g_mem_access[pc]
        if pc > sym_addr and pc < (sym_addr + sym_size):    # we ignore the first instruction
            yield access
#//////SIMENG_MIASM END//////


kallsyms = {
            'arch'          :'',
            'ptr_size'      :0,
            '_start'        :0,
            'numsyms'        :0,
            'address'       :[],
            'type'          :[],
            'name'          :[],
            'address_table'     : 0,
            'name_table'        : 0,
            'type_table'        : 0,
            'token_table'       : 0,
            'table_index_table' : 0,
            'linux_banner' : "",
            }

def INT(offset, vmlinux):
    bytes = kallsyms['ptr_size'] // 8
    s = vmlinux[offset:offset+bytes]
    f = 'I' if bytes==4 else 'Q'
    (num,) = struct.unpack(f, s)
    return num

def INT32(offset, vmlinux):
    s = vmlinux[offset:offset+4]
    (num,) = struct.unpack('I', s)
    return num

def INT64(offset, vmlinux):
    s = vmlinux[offset:offset+8]
    (num,) = struct.unpack('Q', s)
    return num

def SHORT(offset, vmlinux):
    s = vmlinux[offset:offset+2]
    (num,) = struct.unpack('H', s)
    return num

def STRIPZERO(offset, vmlinux, step=4):
    NOTZERO = INT32 if step==4 else INT
    for i in range(offset,len(vmlinux),step):
        if NOTZERO(i, vmlinux):
            return i

def ord_compat(ch):
    try:
        value = ord(ch)
    except TypeError:
        value = ch

    return value

#//////////////////////

def do_token_index_table(kallsyms , offset, vmlinux):
    kallsyms['token_index_table'] = offset
    print_log('[+]kallsyms_token_index_table = ', hex(offset))

def do_token_table(kallsyms, offset, vmlinux):
    kallsyms['token_table'] = offset
    print_log('[+]kallsyms_token_table = ', hex(offset))

    for i in range(offset,len(vmlinux)):
        if SHORT(i,vmlinux) == 0:
            break
    for i in range(i, len(vmlinux)):
        if ord_compat(vmlinux[i]):
            break
    offset = i-2

    do_token_index_table(kallsyms , offset, vmlinux)

def do_marker_table(kallsyms, offset, vmlinux):
    global g_gki_kernel

    kallsyms['marker_table'] = offset
    print_log('[+]kallsyms_marker_table = ', hex(offset))

    if (g_gki_kernel == 1):
        offset += (((kallsyms['numsyms']-1)>>8)+1)*4    # Markers are unsigned int
    else:
        offset += (((kallsyms['numsyms']-1)>>8)+1)*(kallsyms['ptr_size'] // 8)
    offset = STRIPZERO(offset, vmlinux)

    do_token_table(kallsyms, offset, vmlinux)


def do_type_table(kallsyms, offset, vmlinux):
    global g_gki_kernel

    if (g_gki_kernel == 1):
        offset -= 4     # first entry is always 0, thus skipped by STRIPZERO
        do_marker_table(kallsyms, offset, vmlinux)
        return

    flag = True
    for i in range(offset,offset+256*4,4):
        if INT(i, vmlinux) & ~0x20202020 != 0x54545454:
            flag = False
            break

    if flag:
        kallsyms['type_table'] = offset

        while INT(offset, vmlinux):
            offset += (kallsyms['ptr_size'] // 8)
        offset = STRIPZERO(offset, vmlinux)
    else:
        kallsyms['type_table'] = 0

    print_log('[+]kallsyms_type_table = ', hex(kallsyms['type_table']))

    offset -= (kallsyms['ptr_size'] // 8)
    do_marker_table(kallsyms, offset, vmlinux)

def do_name_table(kallsyms, offset, vmlinux):
    kallsyms['name_table'] = offset
    print_log('[+]kallsyms_name_table = ', hex(offset))

    for i in range(kallsyms['numsyms']):
        length = ord_compat(vmlinux[offset])
        offset += length+1
    while offset%4 != 0:
        offset += 1
    offset = STRIPZERO(offset, vmlinux)
    print_log('[+]end of kallsyms_name_table = ', hex(offset))

    do_type_table(kallsyms, offset, vmlinux)

    # decompress name and type
    name_offset = 0
    for i in range(kallsyms['numsyms']):
        offset = kallsyms['name_table']+name_offset
        length = ord_compat(vmlinux[offset])

        offset += 1
        name_offset += length+1

        name = ''
        while length:
            token_index_table_offset = ord_compat(vmlinux[offset])
            xoffset = kallsyms['token_index_table']+token_index_table_offset*2
            token_table_offset = SHORT(xoffset, vmlinux)
            strptr = kallsyms['token_table']+token_table_offset

            while ord_compat(vmlinux[strptr]):
                name += '%c' % ord_compat(vmlinux[strptr])
                strptr += 1

            length -= 1
            offset += 1

        if kallsyms['type_table']:
            kallsyms['type'].append('X')
            kallsyms['name'].append(name)
        else:
            kallsyms['type'].append(name[0])
            kallsyms['name'].append(name[1:])

def do_guess_start_address(kallsyms, vmlinux):
    _startaddr_from_enable_mmu = 0
    _startaddr_from_xstext = 0
    _startaddr_from_banner = 0
    _startaddr_from_processor = 0

    for i in range(kallsyms['numsyms']):
        if kallsyms['name'][i] in ['_text', 'stext', '_stext', '_sinittext', '__init_begin']:
            if hex(kallsyms['address'][i]):
                if _startaddr_from_xstext==0 or kallsyms['address'][i]<_startaddr_from_xstext:
                    _startaddr_from_xstext = kallsyms['address'][i]

        elif kallsyms['name'][i] == '__enable_mmu':
            if kallsyms['arch'] == 'arm64':
                enable_mmu_addr = kallsyms['address'][i]

                '''
                msr ttbr0_el1, x25          // load TTBR0
                msr ttbr1_el1, x26          // load TTBR1
                '''
                enable_mmu_fileoffset = vmlinux.find(b'\x19\x20\x18\xd5\x3a\x20\x18\xd5')

                if enable_mmu_fileoffset != -1:
                    _startaddr_from_enable_mmu = enable_mmu_addr - enable_mmu_fileoffset + 0x40
                    _startaddr_from_enable_mmu = _startaddr_from_enable_mmu & 0xfffffffffffff000
                # print_log('_startaddr_from_enable_mmu = %s' % (hex(_startaddr_from_enable_mmu)))


        elif kallsyms['name'][i] == 'linux_banner':
            linux_banner_addr = kallsyms['address'][i]
            linux_banner_fileoffset = vmlinux.find(b'Linux version ')
            if linux_banner_fileoffset != -1:
                _startaddr_from_banner = linux_banner_addr - linux_banner_fileoffset

        elif kallsyms['name'][i] == '__lookup_processor_type_data':
            lookup_processor_addr = kallsyms['address'][i]

            step = kallsyms['ptr_size'] // 8
            if kallsyms['arch'] == 'arm':
                addr_base = 0xC0008000
            else:
                addr_base = 0xffffff8008080000

            for i in range(0,0x100000,step):
                _startaddr_from_processor = addr_base + i
                fileoffset = lookup_processor_addr - _startaddr_from_processor
                if fileoffset < 0:
                    break
                if fileoffset+step > len(vmlinux):
                    continue
                if lookup_processor_addr == INT(fileoffset, vmlinux):
                    break

            if _startaddr_from_processor == _startaddr_from_processor+0x100000:
                _startaddr_from_processor = 0

    start_addrs = [_startaddr_from_banner, _startaddr_from_enable_mmu, _startaddr_from_processor, _startaddr_from_xstext]
    if kallsyms['arch']==64 and _startaddr_from_banner!=_startaddr_from_xstext:
         start_addrs.append( 0xffffff8008000000 + INT(8, vmlinux) )

    for addr in start_addrs:
        if addr != 0 and addr % 0x1000 == 0:
            if kallsyms['arch'] == 'arm64' and addr < 0xffff000000000000:
                continue
            kallsyms['_start']= addr
            break
    else:
        assert False,"  [!]kernel start address error..."

    return kallsyms['_start']

def do_offset_table(kallsyms, start, vmlinux):
    step = 4    # this is fixed step

    kallsyms['address'] = []
    prev_offset = 0
    relative_base = 0   # We will determine this later

    # status
    #   0: looking for 1st 00 00 00 00
    #   1: looking for 2nd 00 00 00 00
    #   2: looking for non-zero ascending offset seq
    status = 0

    for i in range(start, len(vmlinux), step):
        offset = INT32(i, vmlinux)
        # print hex(i + 0xffffff8008080000), hex(offset)

        if status == 0:
            if offset == 0:
                kallsyms['address'].append(relative_base + offset)
                status = 1
            else:
                return 0
        elif status == 1:
            if offset == 0:
                kallsyms['address'].append(relative_base + offset)
                status = 2
            else:
                return 1
        elif status == 2:
            if (offset > 0) and (offset >= prev_offset) and (offset < 0x8000000) and \
            (prev_offset != 0 or offset - prev_offset < 0xf8000):   # For latest aarch32 kernels, since kallsyms_offsets start with 0xf8000
                kallsyms['address'].append(relative_base + offset)
                prev_offset = offset
            else:
                return (i - start) // step

    return 0

def do_offset_table_alt(kallsyms, start, vmlinux):
    # For some latest GKI kernels, especially 5.0+, offset table looks differently
    step = 4    # this is fixed step

    kallsyms['address'] = []
    prev_offset = 0
    relative_base = 0   # We will determine this later

    # status
    #   0: looking for 1st 00 00 00 00
    #   1: looking for 1nd 00 01 00 00
    #   2: looking for 2nd 00 01 00 00
    #   3: looking for non-zero ascending offset seq
    status = 0
    for i in range(start, len(vmlinux), step):
        offset = INT32(i, vmlinux)

        if status == 0:
            if offset == 0:
                kallsyms['address'].append(relative_base + offset)
                status = 1
            else:
                return 0
        elif status == 1:
            if offset == 0x10000:
                kallsyms['address'].append(relative_base + offset)
                status = 2
            else:
                return 1
        elif status == 2:
            if offset == 0x10000:
                kallsyms['address'].append(relative_base + offset)
                status = 3
            else:
                return 2
        elif status == 3:
            if (offset > 0) and (offset >= prev_offset) and (offset < 0x8000000) and \
            (prev_offset != 0 or offset - prev_offset < 0xf8000):   # For latest aarch32 kernels, since kallsyms_offsets start with 0xf8000
                kallsyms['address'].append(relative_base + offset)
                prev_offset = offset
            else:
                return (i - start) // step

    return 0

def do_offset_table_arm(kallsyms, start, vmlinux):
    step = 4    # this is fixed step

    kallsyms['address'] = []
    prev_offset = 0
    relative_base = 0   # We will determine this later

    # status
    #   0: looking for 1st 00 80 0f 00
    #   1: looking for 2nd 00 80 0f 00
    #   2: looking for non-zero ascending offset seq
    status = 0

    for i in range(start, len(vmlinux), step):
        offset = INT32(i, vmlinux)
        # print hex(i + 0xffffff8008080000), hex(offset)

        if status == 0:
            if offset == 0xf8000:
                kallsyms['address'].append(relative_base + offset)
                status = 1
            else:
                return 0
        elif status == 1:
            if offset == 0xf8000:
                kallsyms['address'].append(relative_base + offset)
                status = 2
                prev_offset = offset
            else:
                return 1
        elif status == 2:
            if (offset > 0) and (offset >= prev_offset) and (offset < 0x80000000):
                kallsyms['address'].append(relative_base + offset)
                prev_offset = offset
            else:
                return (i - start) // step

    return 0


def do_address_table(kallsyms, offset, vmlinux, addr_base_32 = 0xC0000000):
    step = kallsyms['ptr_size'] // 8
    if kallsyms['arch'] == 'arm':
        addr_base = addr_base_32
    else:
        addr_base = 0xffffff8008000000

    kallsyms['address'] = []
    prev_addr = 0
    for i in range(offset, len(vmlinux), step):
        addr = INT(i, vmlinux)
        if addr < addr_base:
            return (i-offset) // step
        elif addr < prev_addr:
            return (i-offset) // step
        else:
            kallsyms['address'].append(addr)
            prev_addr = addr

    return 0

def insert_symbol(name, addr, sym_type):
    idx = bisect.bisect_right(kallsyms['address'], addr)

    # Check if name is duplicate, assuming address is correct
    i = idx - 1
    if i < kallsyms['numsyms']:
        while i >= 0 and kallsyms['address'][i] == addr:
            if kallsyms['name'][i] == name:
                return
            i -= 1

    kallsyms['address'].insert(idx, addr)
    kallsyms['type'].insert(idx, sym_type)
    kallsyms['name'].insert(idx, name)
    kallsyms['numsyms'] += 1

def check_miasm_symbols(vmlinux):
    global args

    if args is None:
        # Most likely laoded in IDA or r2. For now just disable experimental features.
        return
    else:
        if (not miasm_installed) or (not args.miasm):
            return

    print_log('[+]miasm features (experimental) enabled')
    print_log('[+]init miasm engine...')

    miasm_load_vmlinux(kallsyms, vmlinux)

    # selinux_enforcing
    if 'selinux_enforcing' not in kallsyms['name']:
        print_log('[+]selinux_enforcing not found, using miasm to locate it')
        if 'enforcing_setup' not in kallsyms['name']:
            print_log('[!]enforcing setup not found')
        else:
            miasm_set_mem(0x10000000, b'1\x00')
            call_args = {}
            if kallsyms['arch'] == 'arm64':
                call_args['X0'] = 0x10000000
            elif kallsyms['arch'] == 'arm':
                call_args['R0'] = 0x10000000

            loc_selinux_enforcing = 0
            for access in get_mem_access(kallsyms, 'enforcing_setup', call_args):
                # print_log("%s , %s, %d" % (access['dir'], hex(access['addr']), access['len']))
                if access['dir'] == 'write' and access['len'] == 4:
                    loc_selinux_enforcing = access['addr']
                    break

            if loc_selinux_enforcing > 0:
                print_log("[+]found selinux_enforcing @ %s" % (hex(loc_selinux_enforcing)))
                if loc_selinux_enforcing > kallsyms['_start']:
                    insert_symbol('selinux_enforcing', loc_selinux_enforcing, 'B')

        pass

def find_sys_call_table(kallsyms, vmlinux):
    loc_sys_call_table = 0
    symbols = []

    if kallsyms['arch'] == 'arm':
        symbols.append('sys_restart_syscall')
        symbols.append('sys_exit')
        symbols.append('sys_fork')
        symbols.append('sys_read')
        pass
    elif kallsyms['arch'] == 'arm64':
        '''
        #define __NR_io_setup 0
        __SC_COMP(__NR_io_setup, sys_io_setup, compat_sys_io_setup)
        #define __NR_io_destroy 1
        __SYSCALL(__NR_io_destroy, sys_io_destroy)
        #define __NR_io_submit 2
        __SC_COMP(__NR_io_submit, sys_io_submit, compat_sys_io_submit)
        #define __NR_io_cancel 3
        __SYSCALL(__NR_io_cancel, sys_io_cancel)
        '''
        symbols.append('sys_io_setup')
        symbols.append('sys_io_destroy')
        symbols.append('sys_io_submit')
        symbols.append('sys_io_cancel')
        pass
    else:
        return

    print_log('[+]looking for symbols ', symbols)
    addr_string = b''

    for sym in symbols:
        if sym not in kallsyms['name']:
            print_log('[!]%s not found' % (sym))
            return

        idx = kallsyms['name'].index(sym)

        if kallsyms['ptr_size'] == 64:
            addr_string = addr_string + struct.pack('<Q', kallsyms['address'][idx])
        elif kallsyms['ptr_size'] == 32:
            addr_string = addr_string + struct.pack('<L', kallsyms['address'][idx])
        else:
            raise Exception('Invalid ptr_size')

    offset = vmlinux.find(addr_string)
    if offset == -1:
        print_log("[!]Can't find sys_call_table")
        return

    loc_sys_call_table = kallsyms['_start'] + offset
    print_log("[+]Found sys_call_table @ %s" % (hex(loc_sys_call_table)))
    insert_symbol('sys_call_table', loc_sys_call_table, 'R')


def do_kallsyms(kallsyms, vmlinux):
    global g_gki_kernel

    step = kallsyms['ptr_size'] // 8
    min_numsyms = 20000

    offset = 0
    vmlen  = len(vmlinux)
    is_offset_table = 0
    kallsyms_relative_base = 0

    while offset+step < vmlen:
        num = do_address_table(kallsyms, offset, vmlinux)
        if num > min_numsyms:
            if (kallsyms['arch'] == 'arm') or \
            (kallsyms['address'][0] // 0x100000000 == 0xffffffc0 or \
            kallsyms['address'][0] // 0x100000000 == 0xffffff80):
                kallsyms['numsyms'] = num
                break

        offset += (num+1)*step

    # 2G/2G kernel
    if kallsyms['numsyms'] == 0 and kallsyms['arch'] == 'arm':
        print_log('[!]could be 2G/2G kernel...')
        offset = 0
        step = 4
        while offset+step < vmlen:
            num = do_address_table(kallsyms, offset, vmlinux, addr_base_32 = 0x80000000)
            if num > min_numsyms:
                kallsyms['numsyms'] = num
                break
            else:
                offset += (num+1)*step

    if kallsyms['numsyms'] == 0:
        print_log('[!]could be offset table...')
        is_offset_table = 1
        offset = 0
        step = 4
        while offset+step < vmlen:
            num = do_offset_table(kallsyms, offset, vmlinux)

            if num > min_numsyms:
                kallsyms['numsyms'] = num
                break
            else:
                if num > 2:
                    offset += (num) * step
                else:
                    offset += step

        # For some aarch32 kernels, kallsyms_offset beign with 0xf8000
        if kallsyms['numsyms'] == 0 and \
            kallsyms['arch'] == 'arm':
            offset = 0
            while offset+step < vmlen:
                num = do_offset_table_arm(kallsyms, offset, vmlinux)

                if num > min_numsyms:
                    kallsyms['numsyms'] = num
                    break
                else:
                    if num > 2:
                        offset += (num) * step
                    else:
                        offset += step

        # For latest GKI kernels, there could be different offset table
        if kallsyms['numsyms'] == 0:
            print_log('[!]could be alternative offset table...')
            is_offset_table = 1
            offset = 0
            step = 4
            while offset+step < vmlen:
                num = do_offset_table_alt(kallsyms, offset, vmlinux)

                if num > min_numsyms:
                    kallsyms['numsyms'] = num
                    break
                else:
                    if num > 2:
                        offset += (num) * step
                    else:
                        offset += step


        step = kallsyms['ptr_size'] // 8 # recover normal step


    if kallsyms['numsyms'] == 0:
        print_log('[!]lookup_address_table error...')
        return

    print_log('[+]numsyms: ', kallsyms['numsyms'])

    kallsyms['address_table'] = offset
    print_log('[+]kallsyms_address_table = ', hex(offset))

    if is_offset_table == 0:
        offset += kallsyms['numsyms']*step
        offset = STRIPZERO(offset, vmlinux, step)
    else:
        offset += kallsyms['numsyms']*4
        offset = STRIPZERO(offset, vmlinux, 4)
        kallsyms_relative_base = INT(offset, vmlinux)

        # Update addresses
        for idx in range(0, len(kallsyms['address'])):
            kallsyms['address'][idx] += kallsyms_relative_base
        print_log('[+]kallsyms_relative_base = ', hex(kallsyms_relative_base))

        offset += step  # skip kallsyms_relative_base
        offset = STRIPZERO(offset, vmlinux, 4)
    num = INT(offset, vmlinux)
    offset += step


    print_log('[+]kallsyms_num = ', kallsyms['numsyms'], ' (', num, ')')
    if abs(num-kallsyms['numsyms']) > 128:
            kallsyms['numsyms'] = 0
            print_log('  [!]not equal, maybe error...'    )
            return

    if num > kallsyms['numsyms']:
        for i in range(kallsyms['numsyms'],num):
            kallsyms['address'].insert(0,0)
    kallsyms['numsyms'] = num

    offset = STRIPZERO(offset, vmlinux)
    do_name_table(kallsyms, offset, vmlinux)
    do_guess_start_address(kallsyms, vmlinux)
    print_log('[+]kallsyms_start_address = ', hex(kallsyms['_start']))

    # Fix missing _text
    if '_text' not in kallsyms['name']:
        print_log('[+]_text missing, fix by using guessed start')
        kallsyms['address'].insert(0, kallsyms['_start'])
        kallsyms['type'].insert(0, 'T')
        kallsyms['name'].insert(0, '_text')
        kallsyms['numsyms'] += 1

    # fix missing vermagic
    if 'vermagic' not in kallsyms['name']:
        if kallsyms['arch'] == 'arm64':
            pattern = b'(\\d+\\.\\d+\\.\\d+(\\S+)? SMP preempt [a-zA-Z_ ]*aarch64)'
            match = re.search(pattern, vmlinux)
            if match is None:
                pass
            else:
                sym_addr = kallsyms['_start'] + match.start()
                insert_symbol('vermagic', sym_addr, 'r')
                print_log('[!]no vermagic symbol, found @ %s' % (hex(sym_addr)))

    # fix missing linux_banner
    if 'linux_banner' not in kallsyms['name']:
        pattern = b'Linux version \\d+\\.\\d+\\.\\d+'
        match = re.search(pattern, vmlinux)
        if match is None:
            pass
        else:
            sym_addr = kallsyms['_start'] + match.start()
            insert_symbol('linux_banner', sym_addr, 'B')
            print_log('[!]no linux_banner symbol, found @ %s' % (hex(sym_addr)))

    # fix missing sys_call_table
    if 'sys_call_table' not in kallsyms['name']:
        find_sys_call_table(kallsyms, vmlinux)

    check_miasm_symbols(vmlinux)

    find_ksymtab(kallsyms, vmlinux)

    return

def do_get_arch(kallsyms, vmlinux):
    def fuzzy_arm64(vmlinux):
        step = 8
        offset = 0
        vmlen  = len(vmlinux) - len(vmlinux)%8
        addr_base = 0xffffff8008000000
        while offset+step < vmlen:
          for i in range(offset, vmlen, step):
                if INT64(i, vmlinux) < addr_base:
                    addrnum = (i-offset) // step
                    if addrnum > 10000:
                        return True
                    else:
                        offset = i+step
        return False

    if re.search(b'ARMd', vmlinux[:0x200]):
        kallsyms['arch'] = 'arm64'
        kallsyms['ptr_size'] = 64
    elif fuzzy_arm64(vmlinux):
        kallsyms['arch'] = 'arm64'
        kallsyms['ptr_size'] = 64
    else:
        kallsyms['arch'] = 'arm'
        kallsyms['ptr_size'] = 32

    print_log('[+]kallsyms_arch = ', kallsyms['arch'])

def print_kallsyms(kallsyms):
    buf = '\n'.join( '%x %c %s'%(kallsyms['address'][i],kallsyms['type'][i],kallsyms['name'][i]) for i in range(kallsyms['numsyms']) )
    # open('kallsyms','w').write(buf)
    print_sym(buf)

def print_kallsyms_json(kallsyms):
    try:
        kallsyms['linux_banner'] = str(kallsyms['linux_banner'], 'utf-8')
    except:
        pass
    kallsyms_json = json.dumps(kallsyms)
    print_sym(kallsyms_json)

#////////////////////////////////////////////////////////////////////////////////////////////
# Process ksymtab

c_identity_patt = re.compile(b"([_a-zA-Z][_a-zA-Z0-9]*)\\x00")

def is_ksymtab_pair(kallsyms, vmlinux, idx, symlist):
    ptr1 = 0
    ptr2 = 0
    max_size = 128 * 1024 * 1024

    if kallsyms['ptr_size'] == 64:
        (ptr1, ) = struct.unpack("Q", vmlinux[idx:idx+8])
        (ptr2, ) = struct.unpack("Q", vmlinux[idx+8:idx+16])
    elif kallsyms['ptr_size'] == 32:
        (ptr1, ) = struct.unpack("I", vmlinux[idx:idx+4])
        (ptr2, ) = struct.unpack("I", vmlinux[idx+4:idx+8])
    else:
        raise Exception("Unsupported ptr_size")

    # Must be in range
    # if ptr1 < kallsyms['_start'] or ptr1 >= (kallsyms['_start'] + len(vmlinux)):
    if ptr1 < kallsyms['_start'] or ptr1 >= (kallsyms['_start'] + max_size):
        return False
    if ptr2 < kallsyms['_start'] or ptr2 >= (kallsyms['_start'] + len(vmlinux)):
        return False

    # Check if ptr2 if pointing to a null-terminate string representing a valid C identity
    i = ptr2 - kallsyms['_start']
    substr = vmlinux[i:i+256]
    m = c_identity_patt.match(substr)
    if m is None:
        return False

    sym_name = m.group(1)
    try:
        sym_name = sym_name.decode('utf-8')
    except:
        pass
    symlist.append((ptr1, sym_name))
    return True

def find_ksymtab(kallsyms, vmlinux):
    idx = 0
    ksym_count = 0
    ksym_count_threshold = 256
    step = 0

    symlist = []

    if kallsyms['ptr_size'] == 64:
        step = 8
    elif kallsyms['ptr_size'] == 32:
        step = 4
    else:
        raise Exception("Unsupported ptr_size")

    # if we already have __start___ksymtab
    try:
        if idx == 0:
            i = kallsyms['name'].index('__start___ksymtab')
            addr = kallsyms['address'][i]
            idx = addr - kallsyms['_start']
    except:
        pass

    while idx < (len(vmlinux) - step*2):
        if is_ksymtab_pair(kallsyms, vmlinux, idx, symlist):
            ksym_count += 1
            idx += (step * 2)

            if (ksym_count >= ksym_count_threshold):
                break
        else:
            ksym_count = 0
            symlist = []
            idx += step

        continue

    if (ksym_count < ksym_count_threshold):
        print_log("[!]can't locate ksymtab")
        return

    while idx < (len(vmlinux) - step):
        if not is_ksymtab_pair(kallsyms, vmlinux, idx, symlist):
            break
        idx += (step * 2)

    print_log("[+]found %d symbols in ksymtab" % (len(symlist)))

    etext = kallsyms['_start'] + len(vmlinux)
    bss_start = kallsyms['_start'] + len(vmlinux)
    try:
        etext_idx = kallsyms['name'].index('_etext')
        etext = kallsyms['address'][etext_idx]
    except:
        try:
            etext_idx = kallsyms['name'].index('__start_rodata')
            etext = kallsyms['address'][etext_idx]
        except:
            pass

    for (addr, symname) in symlist:
        t = 'd'
        if addr < etext:
            t = 't'
        elif addr < bss_start:
            t = 'd'  # we don't know if it is read-only, don't care either :-S
        else:
            t = 'b'

        insert_symbol(symname, addr, t)

#////////////////////////////////////////////////////////////////////////////////////////////
# IDA Pro Plugin Support

def accept_file(li, n):
    """
    Check if the file is of supported format

    @param li: a file-like object which can be used to access the input data
    @param n : format number. The function will be called with incrementing
               number until it returns zero
    @return: 0 - no more supported formats
             string "name" - format name to display in the chooser dialog
             dictionary { 'format': "name", 'options': integer }
               options: should be 1, possibly ORed with ACCEPT_FIRST (0x8000)
               to indicate preferred format
    """

    # ida 7+ compatibility, n is filename
    # we support only one format per file
    if isinstance(n, int):
        if n > 0:
            return 0

    # magic = li.read(8)
    # if magic != 'ANDROID!':
    #     return 0

    return "Android/Linux Kernel Image(ARM)"

def load_file(li, neflags, format):
    """
    Load the file into database

    @param li: a file-like object which can be used to access the input data
    @param neflags: options selected by the user, see loader.hpp
    @return: 0-failure, 1-ok
    """

    li.seek(0)
    vmlinux = li.read(li.size())

    do_get_arch(kallsyms, vmlinux)
    do_kallsyms(kallsyms, vmlinux)

    if kallsyms['numsyms'] == 0:
        print_log('[!]get kallsyms error...')
        return 0

    idaapi.set_processor_type("arm", idaapi.SETPROC_LOADER_NON_FATAL|idaapi.SETPROC_LOADER)
    if kallsyms['arch'] == 'arm64':
        idaapi.get_inf_structure().lflags |= idaapi.LFLG_64BIT

    li.file2base(0, kallsyms['_start'], kallsyms['_start']+li.size(), True)

    sinittext_addr = 0
    max_sym_addr = 0
    for i in range(kallsyms['numsyms']):
        if kallsyms['arch'] == 'arm':
            if kallsyms['address'][i] > 0xd0000000:
                continue

        if kallsyms['name'][i] == '_sinittext':
            sinittext_addr = kallsyms['address'][i]
        if kallsyms['address'][i] > max_sym_addr:
            max_sym_addr = kallsyms['address'][i]
    max_sym_addr = max_sym_addr + 1024
    print_log("max_sym_addr = ", hex(max_sym_addr))

    if (kallsyms['_start']+li.size()) > max_sym_addr:
        max_sym_addr = kallsyms['_start']+li.size()


    s = idaapi.segment_t()
    s.bitness = kallsyms['ptr_size'] // 32
    s.start_ea = kallsyms['_start']
    if sinittext_addr == 0:
        s.end_ea = max_sym_addr
    else:
        s.end_ea = sinittext_addr
    s.perm = 5
    idaapi.add_segm_ex(s,".text","CODE",idaapi.ADDSEG_OR_DIE)

    if sinittext_addr > 0:
        s = idaapi.segment_t()
        s.bitness = kallsyms['ptr_size'] // 32
        s.start_ea = sinittext_addr
        s.end_ea = max_sym_addr
        s.perm = 7
        idaapi.add_segm_ex(s,".data","DATA",idaapi.ADDSEG_OR_DIE)

    for i in range(kallsyms['numsyms']):
        if kallsyms['type'][i] in ['t','T']:
            idaapi.add_entry(kallsyms['address'][i], kallsyms['address'][i], kallsyms['name'][i], 1)
        else:
            idaapi.add_entry(kallsyms['address'][i], kallsyms['address'][i], kallsyms['name'][i], 0)

    print_log("Android/Linux vmlinux loaded...")
    return 1

#////////////////////////////////////////////////////////////////////////////////////////////
# Radare2 Plugin Support

def r2():
    r2p = r2pipe.open()
    info = r2p.cmdj("ij")
    with open(info["core"]["file"], 'rb') as f:
        vmlinux = f.read()

    do_get_arch(kallsyms, vmlinux)
    do_kallsyms(kallsyms, vmlinux)

    if kallsyms['numsyms'] == 0:
        print_log('[!]get kallsyms error...')
        return 0

    r2p.cmd("e asm.arch = arm")
    r2p.cmd("e asm.bits = %d" % kallsyms['ptr_size'])

    siol_map = r2p.cmdj("omj")[0]["map"]
    set_baddr = "omb " + str(siol_map) + " " + str(kallsyms["_start"])
    r2p.cmd(set_baddr)

    seg = "s 0 " + str(kallsyms["_start"]) + " " + str(len(vmlinux)) + " .text rx"
    r2p.cmd(seg)

    r2p.cmd("fs symbols")
    for i in range(kallsyms['numsyms']):
        if kallsyms["address"][i] == 0:
            continue
        if kallsyms['type'][i] in ['t','T']:
            cmd = "f fcn." + kallsyms["name"][i] + " @ " + str(kallsyms["address"][i])
            r2p.cmd(cmd)
        else:
            cmd = "f sym." + kallsyms["name"][i] + " @ " + str(kallsyms["address"][i])
            r2p.cmd(cmd)

    r2p.cmd("e anal.strings = true")
    r2p.cmd("s " + str(kallsyms["_start"]))

    print_log("Android/Linux vmlinux loaded...")
    return 1

#////////////////////////////////////////////////////////////////////////////////////////////

def parse_vmlinux(filename, log=None, sym=None):
    global log_file
    global sym_file
    global ver_major
    global ver_minor
    global g_gki_kernel

    log_file = log
    sym_file = sym

    if os.path.exists(filename):
        vmlinux = open(filename, 'rb').read()

        pat = re.compile(b"Linux version (\d+)\.(\d+)\.(\d+).*")
        matches = pat.search(vmlinux)
        if matches is None:
            print_log("[!]can't locate linux banner...")
        else:
            kallsyms['linux_banner'] = matches.group(0)
            ver_major = int(matches.group(1))
            ver_minor = int(matches.group(2))
            print_log(kallsyms['linux_banner'])
            print_log("[+]Version: ", ver_major, ".", ver_minor)
            if (ver_major >= 5):
                g_gki_kernel = 1

        do_get_arch(kallsyms, vmlinux)
        do_kallsyms(kallsyms, vmlinux)
    else:
        print_log('[!]vmlinux does not exist...')

def main(argv):
    global args

    parser = argparse.ArgumentParser()
    parser.add_argument("-j", "--json", help="output in json, which can be consumed by other systems", action="store_true")
    parser.add_argument("-m", "--miasm", help="enable miasm simulation engine for non-exported symbols (experimental)", action="store_true")
    parser.add_argument("image", help="kernel image filename", type=str)

    args = parser.parse_args()

    parse_vmlinux(args.image, sys.stderr, sys.stdout)
    if kallsyms['numsyms'] > 0:
        if args.json:
            print_kallsyms_json(kallsyms)
        else:
            print_kallsyms(kallsyms)
    else:
        print_log('[!]get kallsyms error...')

#////////////////////////////////////////////////////////////////////////////////////////////

if idaapi:
    pass
elif radare2:
    import r2pipe
    r2()
else:
    if __name__ == "__main__":
        main(sys.argv)


