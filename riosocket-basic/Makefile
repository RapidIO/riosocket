###############################################################################
# Centaurus Computing Plc
#
#
#
################################################################################

KERNEL_VERSION := $(shell uname -r)
KERNELDIR = /lib/modules/$(KERNEL_VERSION)/build
KERNEL := kernel-$(KERNEL_VERSION)
INSTDIR = /lib/modules/$(KERNEL_VERSION)/kernel/drivers/rapidio
PWD := $(shell pwd)

EXTRA_CFLAGS += -DCONFIG_RAPIDIO_DMA_ENGINE

RIO_SYM := $(PWD)/../../kernel-rapidio/Module.symvers
RIO_INCLUDE := $(M)/../../kernel-rapidio/include/

RIOSOCK_MODULE_OBJ := riosocket
RIOSOCK_SRC_OBJ := riosocket-netdev.o riosocket-riodev.o riosocket-sysfs.o riosocket-msg.o

obj-m := $(RIOSOCK_MODULE_OBJ).o
ccflags-y := -I$(RIO_INCLUDE)
$(RIOSOCK_MODULE_OBJ)-objs := $(RIOSOCK_SRC_OBJ)


all: 
	rm -rf $(KERNEL)
	mkdir $(KERNEL)
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules KBUILD_EXTRA_SYMBOLS=$(RIO_SYM) 
	cp riosocket.ko $(KERNEL)/

install:
	find /lib/modules/$(KERNEL_VERSION) -name riosocket.ko -exec rm -f {} \; || true
	install -D -m 644 $(KERNEL)/riosocket.ko $(INSTDIR)/riosocket.ko
	/sbin/depmod -a $(KERNEL_VERSION) || true
	cp -n riosocket.conf /etc/modprobe.d/

uninstall:
	if [ -e $(INSTDIR)/riosocket.ko ] ; then \
	    rm -f $(INSTDIR)/riosocket.ko ; \
	fi
	/sbin/depmod -a
	rm -rf /etc/modprobe.d/riosocket.conf


clean:
	rm -f *.o *.a *.ko .*.cmd *.mod.c *.order *.symvers *.unsigned
	rm -f -r .tmp_versions
