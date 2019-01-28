# Android/Linux vmlinux loader

*vmlinux.py* is a python script which can load vmlinux image in both IDA Pro and radare2.

## vmlinux

*vmlinux* is a decompressed kernel image, personally I prefer to extract it from *boot.img* by [binwalk](https://github.com/devttys0/binwalk). However, [imgtool](http://newandroidbook.com/tools/imgtool.html) is another good choice.

	./imgtool pixel_boot.img extract
	lz4 -d extracted/kernel ./pixel_vmlinux
	
## usage

### IDA Pro

	vmlinux.py		->		C:\Program Files\IDA x.x\loaders\

### radare2

	r2 -i ./vmlinux.py ./test/pixel_vmlinux

### Command Line

	python ./vmlinux.py ./test/pixel_vmlinux

## KASLR

In some cases, kernel image with KASLR enabled will populate relocation entries upon boot and leave them as 0 in image. fix_kaslr_arm64.c and fix_kaslr_samsung.c can fix these images by re-populating relocation entries with their original addresses.