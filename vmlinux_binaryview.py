# BinaryNinja Plugin Support
# @Author  : NWMonster@hotmail.com

from binaryninja import BackgroundTaskThread, BinaryView, Architecture, Platform, Symbol, log_error, log_warn
from binaryninja.enums import SymbolType, SegmentFlag
from .vmlinux import *

import traceback

class VMLinuxView(BinaryView):

    name = "VMLinux"
    long_name = "VMLinux"

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata = data.file, parent_view = data)
        self.raw = data

    @classmethod
    def is_valid_for_data(cls, data:BinaryView) -> bool:
        if data.read(0x38, 4) == b'ARMd' or data.read(0x21, 4) == b'ARMd':
            return True 
        return False

    def init(self):
        try:
            print(self.file.filename)
            with open(self.file.filename, 'rb') as f:
                vmlinux_context = f.read()
            vmlinux_size = len(vmlinux_context)

            do_get_arch(kallsyms, vmlinux_context)

            if kallsyms['arch'] == "arm64":
                print("Found arch arm64")
                self.arch = Architecture['aarch64']
                self.platform = Platform['linux-aarch64']
            else:
                print('[!]get arch error...')
                return False

            do_kallsyms(kallsyms, vmlinux_context)

            if kallsyms['numsyms'] == 0:
                print('[!]get kallsyms error...')
                return False

            flags = 0
            flags |= SegmentFlag.SegmentContainsData
            flags |= SegmentFlag.SegmentContainsCode
            flags |= SegmentFlag.SegmentReadable
            flags |= SegmentFlag.SegmentExecutable

            log_warn(f"Adding segment {kallsyms['_start']}, {vmlinux_size}, 0, {vmlinux_size}, {flags}")
            self.add_auto_segment(kallsyms["_start"], vmlinux_size, 0, vmlinux_size, flags)
            self.add_auto_section('.text', kallsyms["_start"], vmlinux_size)
            self.add_entry_point(kallsyms["_start"])

            for i in range(kallsyms['numsyms']):
                if kallsyms["address"][i] == 0:
                    continue
                if kallsyms['type'][i] in ['t','T']:
                    sym = Symbol(SymbolType.FunctionSymbol, kallsyms["address"][i], kallsyms["name"][i])
                    self.define_auto_symbol(sym)
                    self.create_user_function(kallsyms["address"][i], self.platform)
                else:
                    sym = Symbol(SymbolType.DataSymbol, kallsyms["address"][i], kallsyms["name"][i])
                    self.define_auto_symbol(sym)

            f.close()
        except:
            log_error(traceback.format_exc())
            return False

        return True

#VMLinuxView.register()

