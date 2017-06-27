Android vmlinux loader
======================
	
**INSTALL**

	droidimg.py		->		C:\Program Files\IDA 6.x\loaders\

**KASLR**

In some cases, kernel image with KASLR enabled will populate relocation entries upon boot and leave them as 0 in image. fix_kaslr_4_4.c and fix_kaslr_samsung.c can fix these images by re-populating relocation entries with their original addresses.

**TODO**

	todo.