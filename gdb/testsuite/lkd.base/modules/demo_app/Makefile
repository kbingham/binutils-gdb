
# requiers :
#
#	export ARCH=[sh][arm]
#	export CROSS_COMPILE=[sh4-linux-][arm toolchain]
#	export INSTALL_MOD_PATH=[/opt/../target]

BINDIR=$INSTALL_MOD_PATH/bin
LIBDIR=$INSTALL_MOD_PATH/lib
INCDIR=$INSTALL_MOD_PATH/usr/include

EXTRA_CFLAGS= -g -D_GNU_SOURCE -Wall -lpthread

obj-m := fake_alsa.o 

all: other

other:
	make -C $(KDIR) / M=`pwd` modules modules_install
	$(CROSS_COMPILE)gcc -DARCH_$(ARCH) $(EXTRA_CFLAGS) -L$(LIBDIR) -o $(ARCH)_demo_app fake_app.c 
	cp fake*.ko $(INSTALL_MOD_PATH)/root
	cp $(ARCH)_demo_app $(INSTALL_MOD_PATH)/root/demo_app
	cp my_* $(INSTALL_MOD_PATH)/bin
	cp load* $(INSTALL_MOD_PATH)/root
	cp start* $(INSTALL_MOD_PATH)/root
	cp send_* $(INSTALL_MOD_PATH)/root

intel: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc $(EXTRA_CFLAGS) -o demo_app fake_app.c

clean:
	rm -fr .*.cmd .tmp_versions *.symvers *.o *.o.S *.ko *.mod.c *.order *~ *demo_app a.out




