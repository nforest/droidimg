#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import os
import re
import sys
import time
import struct

import json
import argparse

from builtins import range

#////////////////////////////////////////////////////////////////////////////////////////////

try:
    import idaapi
except:
    idaapi = None

radare2 = True if 'R2PIPE_IN' in os.environ else False


#////////////////////////////////////////////////////////////////////////////////////////////

kallsyms = {
            'arch'          :0,
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

def INT(offset, vmlinux):
    bytes = kallsyms['arch'] // 8
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
    kallsyms['marker_table'] = offset   
    print_log('[+]kallsyms_marker_table = ', hex(offset))

    offset += (((kallsyms['numsyms']-1)>>8)+1)*(kallsyms['arch'] // 8)
    offset = STRIPZERO(offset, vmlinux)

    do_token_table(kallsyms, offset, vmlinux)


def do_type_table(kallsyms, offset, vmlinux):
    flag = True
    for i in range(offset,offset+256*4,4):
        if INT(i, vmlinux) & ~0x20202020 != 0x54545454:
            flag = False
            break

    if flag:
        kallsyms['type_table'] = offset

        while INT(offset, vmlinux):
            offset += (kallsyms['arch'] // 8)
        offset = STRIPZERO(offset, vmlinux)
    else:
        kallsyms['type_table'] = 0
    
    print_log('[+]kallsyms_type_table = ', hex(kallsyms['type_table']))

    offset -= (kallsyms['arch'] // 8)
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
            if kallsyms['arch'] == 64:
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

            step = kallsyms['arch'] // 8
            if kallsyms['arch'] == 32:
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
            if kallsyms['arch'] == 64 and addr < 0xffff000000000000:
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
            if (offset > 0) and (offset >= prev_offset) and (offset < 0x80000000) and \
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
    step = kallsyms['arch'] // 8
    if kallsyms['arch'] == 32:
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

def do_kallsyms(kallsyms, vmlinux):
    step = kallsyms['arch'] // 8
    min_numsyms = 20000

    offset = 0
    vmlen  = len(vmlinux)
    is_offset_table = 0
    kallsyms_relative_base = 0

    while offset+step < vmlen:
        num = do_address_table(kallsyms, offset, vmlinux)
        if num > min_numsyms:
            if (kallsyms['arch'] == 32) or \
            (kallsyms['address'][0] // 0x100000000 == 0xffffffc0 or \
            kallsyms['address'][0] // 0x100000000 == 0xffffff80):
                kallsyms['numsyms'] = num
                break

        offset += (num+1)*step

    # 2G/2G kernel
    if kallsyms['numsyms'] == 0 and kallsyms['arch'] == 32:
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
            kallsyms['arch'] == 32:
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


        step = kallsyms['arch'] // 8 # recover normal step


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
        if kallsyms['arch'] == 64:
            pattern = b'(\\d+\\.\\d+\\.\\d+(\\S+)? SMP preempt [a-zA-Z_ ]*aarch64)'
            match = re.search(pattern, vmlinux)
            if match is None:
                pass
            else:
                sym_addr = kallsyms['_start'] + match.start()
                kallsyms['address'].append(sym_addr)
                kallsyms['type'].append('r')
                kallsyms['name'].append('vermagic')
                kallsyms['numsyms'] += 1
                print_log('[!]no vermagic symbol, found @ %s' % (hex(sym_addr)))

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
        kallsyms['arch'] = 64
    elif fuzzy_arm64(vmlinux):
        kallsyms['arch'] = 64
    else:
        kallsyms['arch'] = 32

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
    if isinstance(n, (int, long)):
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
    
    idaapi.set_processor_type("arm", idaapi.SETPROC_ALL|idaapi.SETPROC_FATAL)
    if kallsyms['arch'] == 64:
        idaapi.get_inf_structure().lflags |= idaapi.LFLG_64BIT

    li.file2base(0, kallsyms['_start'], kallsyms['_start']+li.size(), True)

    sinittext_addr = 0
    max_sym_addr = 0
    for i in range(kallsyms['numsyms']):
        if kallsyms['arch'] == 32:
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
    s.bitness = kallsyms['arch'] // 32
    s.startEA = kallsyms['_start']
    if sinittext_addr == 0:
        s.endEA = max_sym_addr
    else:
        s.endEA = sinittext_addr
    s.perm = 5
    idaapi.add_segm_ex(s,".text","CODE",idaapi.ADDSEG_OR_DIE)
    
    if sinittext_addr > 0:
        s = idaapi.segment_t()
        s.bitness = kallsyms['arch'] // 32
        s.startEA = sinittext_addr
        s.endEA = max_sym_addr
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
    r2p.cmd("e asm.bits = %d" % kallsyms['arch'])

    siol_map = r2p.cmdj("omj")[0]["map"]
    set_baddr = "omr " + str(siol_map) + " " + str(kallsyms["_start"])
    r2p.cmd(set_baddr)

    seg = "S 0 " + str(kallsyms["_start"]) + " " + str(len(vmlinux)) + " .text rx"
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

    log_file = log
    sym_file = sym

    if os.path.exists(filename):
        vmlinux = open(filename, 'rb').read()

        pat = re.compile(b"Linux version \d+\.\d+\.\d+.*")
        matches = pat.search(vmlinux)
        if matches is None:
            print_log("[!]can't locate linux banner...")
        else:
            kallsyms['linux_banner'] = matches.group(0)
            print_log(kallsyms['linux_banner'])

        do_get_arch(kallsyms, vmlinux)
        do_kallsyms(kallsyms, vmlinux)
    else:
        print_log('[!]vmlinux does not exist...')

def main(argv):
    global args

    parser = argparse.ArgumentParser()
    parser.add_argument("-j", "--json", help="output in json, which can be consumed by other systems", action="store_true")
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
        
