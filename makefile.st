.PHONY: all configure% build% install% clean%

################################################################################
CPUARCHLIST.stlinux=armv7 armv7_uclibc sh4 sh4_uclibc
CPUARCHLIST.bare=armv7_bare cross_armv7_bare sh4_bare
#
CPUARCHLIST=$(CPUARCHLIST.stlinux) $(CPUARCHLIST.bare)

ifeq ($(CPUARCH),)
CPUARCH=armv7
else
ifeq ($(filter $(CPUARCH),$(CPUARCHLIST)),)
$(error CPUARCH not recognised ($(CPUARCH)), choose $(CPUARCHLIST))
endif
endif

################################################################################

ifeq ($(BUILDROOT),)
BUILDROOT=$(CURDIR)
endif

ifeq ($(DISTDIR),)
DISTDIR=$(BUILDROOT)/install/$(CPUARCH)
endif

ifeq ($(OBJDIR),)
OBJDIR=$(BUILDROOT)/objects/$(CPUARCH)
endif

################################################################################

ifneq ($(findstring cross,$(CPUARCH)),)
include $(CURDIR)/build.def
endif

################################################################################

all: build install

################################################################################

ifneq ($(filter $(CPUARCH),$(CPUARCHLIST.stlinux)),)
INSTALLTARGETS=install_host_gdb # install_target_gdb install_target_gdbserver
else
INSTALLTARGETS=install_bare_gdb
endif

install: build $(INSTALLTARGETS)

install_host_gdb: $(OBJDIR)/host/Makefile
	$(MAKE) -C $(OBJDIR)/host install

install_target_gdb: $(OBJDIR)/target/Makefile
	$(MAKE) -C $(OBJDIR)/target install

install_target_gdbserver: $(OBJDIR)/target/gdb/gdbserver/Makefile
	$(MAKE) -C $(OBJDIR)/target/gdb/gdbserver install

install_bare_gdb: $(OBJDIR)/Makefile
	$(MAKE) -C $(OBJDIR) install

################################################################################

ifneq ($(filter $(CPUARCH),$(CPUARCHLIST.stlinux)),)
BUILDTARGETS=build_host_gdb ### build_target_gdb build_target_gdbserver
else
BUILDTARGETS=build_bare_gdb
endif

build: $(BUILDTARGETS)

build_host_gdb: $(OBJDIR)/host/Makefile
	$(MAKE) -C $(OBJDIR)/host

build_target_gdb: $(OBJDIR)/target/Makefile
	$(MAKE) -C $(OBJDIR)/target

build_target_gdbserver: $(OBJDIR)/target/gdb/gdbserver/Makefile
	$(MAKE) -C $(OBJDIR)/target/gdb/gdbserver

build_bare_gdb: $(OBJDIR)/Makefile
	$(MAKE) -C $(OBJDIR)

################################################################################

$(OBJDIR)/host/Makefile:
	$(MAKE) -f makefile.st configure_host_$(CPUARCH)_gdb

$(OBJDIR)/target/Makefile:
	$(MAKE) -f makefile.st configure_target_$(CPUARCH)_gdb

$(OBJDIR)/target/gdb/gdbserver/Makefile:
	$(MAKE) -f makefile.st configure_target_$(CPUARCH)_gdbserver

$(OBJDIR)/Makefile:
	$(MAKE) -f makefile.st configure_bare_$(CPUARCH)_gdb

################################################################################

ifneq ($(filter $(CPUARCH),$(CPUARCHLIST.stlinux)),)
CONFIGURETARGETS=configure_host_$(CPUARCH) # configure_target_$(CPUARCH)
else
CONFIGURETARGETS=configure_bare_$(CPUARCH)
endif

configure: $(CONFIGURETARGETS)

configure_host_$(CPUARCH): configure_host_$(CPUARCH)_gdb

configure_target_$(CPUARCH): configure_target_$(CPUARCH)_gdb configure_target_$(CPUARCH)_gdbserver

configure_bare_$(CPUARCH): configure_bare_$(CPUARCH)_gdb

################################################################################

configure_host_armv7_gdb:
	-mkdir -p $(OBJDIR)/host
	cd $(OBJDIR)/host && CC="gcc -m32" $(CURDIR)/configure \
		--prefix=$(DISTDIR) \
		--target=arm-elf-linux \
		--program-prefix=armv7-linux- \
		--disable-nls \
		--enable-linux-kernel-aware \
		--enable-shtdi \
		--enable-tui \
		--with-python=no \
		--with-sysroot=/opt/STM/STLinux-2.4/devkit/armv7/target \
		--with-separate-debug-dir=/opt/STM/STLinux-2.4/devkit/armv7/target/usr/lib/debug

configure_target_armv7_gdb:
	-mkdir -p $(OBJDIR)/target
	cd $(OBJDIR)/target && CC="armv7-linux-gcc" AR="armv7-linux-ar" $(CURDIR)/configure \
		--prefix=$(DISTDIR)/target \
		--host=arm-cortex-linux-gnueabi \
		--target=arm-cortex-linux-gnueabi \
		--disable-nls \
		--with-python=no \
		--with-separate-debug-dir=/usr/lib/debug

configure_target_armv7_gdbserver:
	-mkdir -p $(OBJDIR)/target/gdb/gdbserver
	cd $(OBJDIR)/target/gdb/gdbserver && CC="armv7-linux-gcc" $(CURDIR)/gdb/gdbserver/configure \
		--prefix=$(DISTDIR)/target \
		--host=arm-cortex-linux-gnueabi \
		--target=arm-cortex-linux-gnueabi

################################################################################

configure_host_armv7_uclibc_gdb:
	-mkdir -p $(OBJDIR)/host
	cd $(OBJDIR)/host && CC="gcc -m32" $(CURDIR)/configure \
		--prefix=$(DISTDIR) \
		--target=arm-elf-linux-uclibc \
		--program-prefix=armv7-linux-uclibc- \
		--disable-nls \
		--enable-linux-kernel-aware \
		--enable-shtdi \
		--with-python=no \
		--with-sysroot=/opt/STM/STLinux-2.4/devkit/armv7_uclibc/target \
		--with-separate-debug-dir=/opt/STM/STLinux-2.4/devkit/armv7_uclibc/target/usr/lib/debug

configure_target_armv7_uclibc_gdb:
	-mkdir -p $(OBJDIR)/target
	cd $(OBJDIR)/target && CC="armv7-linux-uclibc-gcc" AR="armv7-linux-uclibc-ar" $(CURDIR)/configure \
		--prefix=$(DISTDIR)/target \
		--host=arm-cortex-linux-uclibcgnueabi \
		--target=arm-cortex-linux-uclibcgnueabi \
		--disable-nls \
		--with-python=no \
		--with-separate-debug-dir=/usr/lib/debug

configure_target_armv7_uclibc_gdbserver:
	-mkdir -p $(OBJDIR)/target/gdb/gdbserver
	cd $(OBJDIR)/target/gdb/gdbserver && CC="armv7-linux-uclibc-gcc" $(CURDIR)/gdb/gdbserver/configure \
		--prefix=$(DISTDIR)/target \
		--host=arm-cortex-linux-uclibcgnueabi \
		--target=arm-cortex-linux-uclibcgnueabi

################################################################################

configure_bare_armv7_bare_gdb:
	-mkdir -p $(OBJDIR)
	cd $(OBJDIR) && CC="gcc -m32" $(CURDIR)/configure \
		--prefix=$(DISTDIR) \
		--target=arm-none-eabi \
		--disable-nls \
		--enable-shtdi \
		--with-python=no \
		--with-sysroot=/opt/STM/STLinux-2.4/bare/armv7

################################################################################

configure_bare_cross_armv7_bare_gdb:
	-mkdir -p $(OBJDIR)
	cd $(OBJDIR) && CC="$(CC) -m32" $(CURDIR)/configure \
		--prefix=$(DISTDIR) \
		--host=i686-pc-mingw32 \
		--target=arm-none-eabi \
		--disable-nls \
		--enable-shtdi \
		--with-python=no 

################################################################################


configure_host_sh4_gdb:
	-mkdir -p $(OBJDIR)/host
	cd $(OBJDIR)/host && CC="gcc -m32" $(CURDIR)/configure \
		--prefix=$(DISTDIR) \
		--target=sh-elf-linux \
		--program-prefix=sh4-linux- \
		--disable-nls \
		--enable-linux-kernel-aware \
		--enable-shtdi \
		--with-python=no \
		--with-sysroot=/opt/STM/STLinux-2.4/devkit/sh4/target \
		--with-separate-debug-dir=/opt/STM/STLinux-2.4/devkit/sh4/target/usr/lib/debug

configure_target_sh4_gdb:
	-mkdir -p $(OBJDIR)/target
	cd $(OBJDIR)/target && CC="sh4-linux-gcc" AR="sh4-linux-ar" $(CURDIR)/configure \
		--prefix=$(DISTDIR)/target \
		--host=sh-elf-linux \
		--target=sh-elf-linux \
		--disable-nls \
		--with-python=no \
		--with-separate-debug-dir=/usr/lib/debug

configure_target_sh4_gdbserver:
	-mkdir -p $(OBJDIR)/target/gdb/gdbserver
	cd $(OBJDIR)/target/gdb/gdbserver && CC="sh4-linux-gcc" $(CURDIR)/gdb/gdbserver/configure \
		--prefix=$(DISTDIR)/target \
		--host=sh-elf-linux \
		--target=sh-elf-linux

################################################################################

configure_host_sh4_uclibc_gdb:
	-mkdir -p $(OBJDIR)/host
	cd $(OBJDIR)/host && CC="gcc -m32" $(CURDIR)/configure \
		--prefix=$(DISTDIR) \
		--target=sh-elf-linux-uclibc \
		--program-prefix=sh4-linux-uclibc- \
		--disable-nls \
		--enable-linux-kernel-aware \
		--enable-shtdi \
		--with-python=no \
		--with-sysroot=/opt/STM/STLinux-2.4/devkit/sh4_uclibc/target \
		--with-separate-debug-dir=/opt/STM/STLinux-2.4/devkit/sh4_uclibc/target/usr/lib/debug

configure_target_sh4_uclibc_gdb:
	-mkdir -p $(OBJDIR)/target
	cd $(OBJDIR)/target && CC="sh4-linux-uclibc-gcc" AR="sh4-linux-uclibc-ar" $(CURDIR)/configure \
		--prefix=$(DISTDIR)/target \
		--host=sh-elf-linux-uclibc \
		--target=sh-elf-linux-uclibc \
		--disable-nls \
		--with-python=no \
		--with-separate-debug-dir=/usr/lib/debug

configure_target_sh4_uclibc_gdbserver:
	-mkdir -p $(OBJDIR)/target/gdb/gdbserver
	cd $(OBJDIR)/target/gdb/gdbserver && CC="sh4-linux-uclibc-gcc" $(CURDIR)/gdb/gdbserver/configure \
		--prefix=$(DISTDIR)/target \
		--host=sh-elf-linux-uclibc \
		--target=sh-elf-linux-uclibc

################################################################################

configure_bare_sh4_bare_gdb:
	-mkdir -p $(OBJDIR)
	cd $(OBJDIR) && CC="gcc -m32" $(CURDIR)/configure \
		--prefix=$(DISTDIR) \
		--target=sh-superh-elf \
		--disable-nls \
		--enable-shtdi \
		--with-python=no \
		--with-sysroot=/opt/STM/STLinux-2.4/bare/sh4

################################################################################

ifneq ($(filter $(CPUARCH),$(CPUARCHLIST.stlinux)),)
CLEANTARGETS=clean_host clean_target
else
CLEANTARGETS=clean_bare
endif

clean: $(CLEANTARGETS)

clean_host:
	-rm -rf $(OBJDIR)/host

clean_target:
	-rm -rf $(OBJDIR)/target

clean_bare:
	-rm -rf $(OBJDIR)

################################################################################

git-setup-clone:
	cd .git && (rm -rf hooks && ln -s ../git_hooks hooks)

################################################################################
