#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2014-08-27 21:49:19
# @Author  : nforest@live.cn

import os
import re
import sys
import time
import struct

try:
    import idaapi
    ida = True
except:
    ida = False

#////////////////////////////////////////////////////////////////////////////////////////////

kallsyms = {
            'arch'          :32,
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
            }

def INT(offset, vmlinux):
    bytes = kallsyms['arch'] / 8
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
    for i in xrange(offset,len(vmlinux),step):
        if NOTZERO(i, vmlinux):
            return i

#//////////////////////

def do_token_index_table(kallsyms , offset, vmlinux):
    kallsyms['token_index_table'] = offset  
    print '[+]kallsyms_token_index_table = ', hex(offset)

def do_token_table(kallsyms, offset, vmlinux):
    kallsyms['token_table'] = offset    
    print '[+]kallsyms_token_table = ', hex(offset)

    for i in xrange(offset,len(vmlinux)):
        if SHORT(i,vmlinux) == 0:
            break
    for i in xrange(i, len(vmlinux)):
        if ord(vmlinux[i]):
            break
    offset = i-2

    do_token_index_table(kallsyms , offset, vmlinux)

def do_marker_table(kallsyms, offset, vmlinux):
    kallsyms['marker_table'] = offset   
    print '[+]kallsyms_marker_table = ', hex(offset)

    offset += (((kallsyms['numsyms']-1)>>8)+1)*(kallsyms['arch']/8)
    offset = STRIPZERO(offset, vmlinux)

    do_token_table(kallsyms, offset, vmlinux)


def do_type_table(kallsyms, offset, vmlinux):
    flag = True
    for i in xrange(offset,offset+256*4,4):
        if INT(i, vmlinux) & ~0x20202020 != 0x54545454:
            flag = False
            break

    if flag:
        kallsyms['type_table'] = offset

        while INT(offset, vmlinux):
            offset += (kallsyms['arch']/8)
        offset = STRIPZERO(offset, vmlinux)
    else:
        kallsyms['type_table'] = 0
    
    print '[+]kallsyms_type_table = ', hex(kallsyms['type_table'])

    offset -= (kallsyms['arch']/8)
    do_marker_table(kallsyms, offset, vmlinux)
            
def do_name_table(kallsyms, offset, vmlinux):
    kallsyms['name_table'] = offset 
    print '[+]kallsyms_name_table = ', hex(offset)

    for i in xrange(kallsyms['numsyms']):
        length = ord(vmlinux[offset])
        offset += length+1
    while offset%4 != 0:
        offset += 1
    offset = STRIPZERO(offset, vmlinux)

    do_type_table(kallsyms, offset, vmlinux)

    # decompress name and type
    name_offset = 0
    for i in xrange(kallsyms['numsyms']):
        offset = kallsyms['name_table']+name_offset
        length = ord(vmlinux[offset])

        offset += 1
        name_offset += length+1

        name = ''
        while length:
            token_index_table_offset = ord(vmlinux[offset])
            xoffset = kallsyms['token_index_table']+token_index_table_offset*2
            token_table_offset = SHORT(xoffset, vmlinux)
            strptr = kallsyms['token_table']+token_table_offset

            while ord(vmlinux[strptr]):
                name += '%c' % ord(vmlinux[strptr])
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
    _startaddr_from_xstext = 0
    _startaddr_from_banner = 0
    _startaddr_from_processor = 0
    
    for i in xrange(kallsyms['numsyms']):
        if kallsyms['name'][i] in ['_text', 'stext', '_stext', '_sinittext', '__init_begin']:
            if hex(kallsyms['address'][i]):
                if _startaddr_from_xstext==0 or kallsyms['address'][i]<_startaddr_from_xstext:
                    _startaddr_from_xstext = kallsyms['address'][i]
        
        elif kallsyms['name'][i] == 'linux_banner':
            linux_banner_addr = kallsyms['address'][i]
            linux_banner_fileoffset = vmlinux.find('Linux version ')
            if linux_banner_fileoffset:
                _startaddr_from_banner = linux_banner_addr - linux_banner_fileoffset

        elif kallsyms['name'][i] == '__lookup_processor_type_data':
            lookup_processor_addr = kallsyms['address'][i]

            step = kallsyms['arch'] / 8
            if kallsyms['arch'] == 32:
                addr_base = 0xC0008000
            else:
                addr_base = 0xffffffc000080000
        
            for i in xrange(0,0x100000,step):
                _startaddr_from_processor = addr_base + i
                fileoffset = lookup_processor_addr - _startaddr_from_processor
                if fileoffset+step > len(vmlinux):
                    continue
                if lookup_processor_addr == INT(fileoffset, vmlinux):
                    break

            if _startaddr_from_processor == _startaddr_from_processor+0x100000:
                _startaddr_from_processor = 0

    start_addrs = [_startaddr_from_banner, _startaddr_from_processor, _startaddr_from_xstext]
    if kallsyms['arch']==64 and _startaddr_from_banner!=_startaddr_from_xstext:
         start_addrs.append( 0xffffffc000000000 + INT(8, vmlinux) )

    # print '[+]kallsyms_guess_start_addresses = ',  hex(0xffffffc000000000 + INT(8, vmlinux)) if kallsyms['arch']==64 else '', hex(_startaddr_from_banner), hex(_startaddr_from_processor), hex(_startaddr_from_xstext)
    
    for addr in start_addrs:
        if addr % 0x1000 == 0:
            kallsyms['_start']= addr
            break
    else:
        assert False,"  [!]kernel start address error..."

    return kallsyms['_start']

def do_address_table(kallsyms, offset, vmlinux):
    step = kallsyms['arch'] / 8
    if kallsyms['arch'] == 32:
        addr_base = 0xC0000000
    else:
        addr_base = 0xffffffc000000000

    kallsyms['address'] = []
    for i in xrange(offset, len(vmlinux), step):
        addr = INT(i, vmlinux)
        if addr < addr_base:
            return (i-offset)/step
        else:
            kallsyms['address'].append(addr)

    return 0

def do_kallsyms(kallsyms, vmlinux):
    step = kallsyms['arch'] / 8

    offset = 0
    vmlen  = len(vmlinux)
    while offset+step < vmlen:
        num = do_address_table(kallsyms, offset, vmlinux)
        if num > 30000:
            kallsyms['numsyms'] = num
            break
        else:
            offset += (num+1)*step

    if kallsyms['numsyms'] == 0:
        print '[!]lookup_address_table error...'
        return

    kallsyms['address_table'] = offset  
    print '[+]kallsyms_address_table = ', hex(offset)

    offset += kallsyms['numsyms']*step
    offset = STRIPZERO(offset, vmlinux, step)
    num = INT(offset, vmlinux)
    offset += step

    print '[+]kallsyms_num = ', kallsyms['numsyms'], num
    if abs(num-kallsyms['numsyms']) > 128:
            kallsyms['numsyms'] = 0
            print '  [!]not equal, maybe error...'    
            return

    if num > kallsyms['numsyms']:
        for i in xrange(kallsyms['numsyms'],num):
            kallsyms['address'].insert(0,0)
    kallsyms['numsyms'] = num

    offset = STRIPZERO(offset, vmlinux)
    do_name_table(kallsyms, offset, vmlinux)
    do_guess_start_address(kallsyms, vmlinux)
    print '[+]kallsyms_start_address = ', hex(kallsyms['_start'])
    return

def do_get_arch(kallsyms, vmlinux):
    def fuzzy_arm64(vmlinux):
        step = 8
        offset = 0
        vmlen  = len(vmlinux) - len(vmlinux)%8
        addr_base = 0xffffffc000000000
        while offset+step < vmlen:
          for i in xrange(offset, vmlen, step):
                if INT64(i, vmlinux) < addr_base:
                    addrnum = (i-offset)/step
                    if addrnum > 10000:
                        return True
                    else:
                        offset = i+step
        return False

    if re.search('ARMd', vmlinux[:0x200]):
        kallsyms['arch'] = 64
    elif fuzzy_arm64(vmlinux):
        kallsyms['arch'] = 64
    else:
        kallsyms['arch'] = 32

    print '[+]kallsyms_arch = ', kallsyms['arch']

#/////////////


def print_kallsyms(kallsyms, vmlinux):
    buf = '\n'.join( '%x %c %s'%(kallsyms['address'][i],kallsyms['type'][i],kallsyms['name'][i]) for i in xrange(kallsyms['numsyms']) ) 
    open('kallsyms','w').write(buf)

#////////////////////////////////////////////////////////////////////////////////////////////

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

    # we support only one format per file
    if n > 0:
        return 0

    # magic = li.read(8)
    # if magic != 'ANDROID!':
    #     return 0

    return "Android OS Kernel(ARM)"

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
    # print_kallsyms(kallsyms, vmlinux)
    
    if kallsyms['numsyms'] == 0:
        print '[!]get kallsyms error...'
        return 0
    
    idaapi.set_processor_type("arm", SETPROC_ALL|SETPROC_FATAL)
    if kallsyms['arch'] == 64:
        idaapi.get_inf_structure().lflags |= idaapi.LFLG_64BIT

    li.file2base(0, kallsyms['_start'], kallsyms['_start']+li.size(), True)

    s = idaapi.segment_t()
    s.bitness = kallsyms['arch'] / 32
    s.startEA = kallsyms['_start']
    s.endEA = kallsyms['_start']+li.size()
    idaapi.add_segm_ex(s,".text","CODE",ADDSEG_OR_DIE)
    
    for i in xrange(kallsyms['numsyms']):
        if kallsyms['type'][i] in ['t','T']:
            idaapi.add_entry(kallsyms['address'][i], kallsyms['address'][i], kallsyms['name'][i], 1)
        else:
            idaapi.add_entry(kallsyms['address'][i], kallsyms['address'][i], kallsyms['name'][i], 0)

    print "Android vmlinux loaded..."
    return 1

#////////////////////////////////////////////////////////////////////////////////////////////

def help():
    print 'Usage:  vmlinux.py [vmlinux FILE]\n'
    exit()

def main(argv):
    if len(argv)!=2:
        help()

    if os.path.exists(argv[1]):
        vmlinux = open(argv[1],'rb').read()
        do_get_arch(kallsyms, vmlinux)
        do_kallsyms(kallsyms, vmlinux)
        if kallsyms['numsyms'] > 0:
            print_kallsyms(kallsyms, vmlinux)
        else:
            print '[!]get kallsyms error...'
    else:
        print '[!]vmlinux does not exist...'
    
if not ida:
    main(sys.argv)
