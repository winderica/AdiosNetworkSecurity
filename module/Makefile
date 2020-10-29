KERN_DIR = /lib/modules/$(shell uname -r)/build
obj-m += lkm.o
ccflags-y := -std=gnu99 -Wno-declaration-after-statement -Wno-implicit-fallthrough -Wno-vla

all:
	make -C $(KERN_DIR) M=$(shell pwd) modules
clean:
	make -C $(KERN_DIR) M=$(shell pwd) modules clean
