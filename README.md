# Android/Linux vmlinux loader

*vmlinux.py* is a python script which can load vmlinux image in both IDA Pro and radare2.

## vmlinux

*vmlinux* is a decompressed kernel image, personally I prefer to extract it from *boot.img* by [binwalk](https://github.com/devttys0/binwalk). However, [imgtool](http://newandroidbook.com/tools/imgtool.html) is another good choice.

	./imgtool pixel_boot.img extract
	lz4 -d extracted/kernel ./pixel_vmlinux

## is this file a valid vmlinux image?

Droidimg is designed for **modern** Linux kernels on Android devices. Since then, it support 3.4+ kernel in arm or arm64 architecture. To quickly determine if you have a valid vmlinux image:

1. Try strings and grep:

```
strings vmlinux | grep "Linux version "
```

If there is no output like this linux banner string, then you don't have a valid vmlinux file. Extracting vmlinux can be complex on some devices, search XDA for guidance.

```
Linux version 4.9.17-g8ab68b3b (ubuntu@A7Linux) (gcc version 4.9.x 20150123 (prerelease) (GCC) ) #1 SMP PREEMPT Sat Jan 12 15:51:20 CST 2019
```

2. If the script failed to determine the architecture, most likely the architecture is unsupported.

3. Some boot image with UNCOMPRESSED kernel has a 20 bytes header in front of kernel text. Strip it and try again.

	
## usage

### IDA Pro

	vmlinux.py		->		C:\Program Files\IDA x.x\loaders\

### radare2

	r2 -i ./vmlinux.py ./test/pixel_vmlinux

### Command Line

	python ./vmlinux.py ./test/pixel_vmlinux

	Use -j/--json to produce json output, which can be consumed by other components

	Use -m/--miasm to enable miasm simulation engine in case some symbols are not exported (experimental). Note that only Python 2 is supported by miasm for now.

	Miasm: https://github.com/cea-sec/miasm

## KASLR

In some cases, kernel image with KASLR enabled will populate relocation entries upon boot and leave them as 0 in image. fix_kaslr_arm64.c and fix_kaslr_samsung.c can fix these images by re-populating relocation entries with their original addresses.

## CI Status

[![Build Status](https://travis-ci.org/idl3r/droidimg.svg?branch=master)](https://travis-ci.org/idl3r/droidimg)
