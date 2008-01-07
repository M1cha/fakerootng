SUBDIRS=tests 


.PHONY: build_lib
build_lib:
	$(MAKE) -C arch/$(target_os)/$(target_cpu)

clean-local:
	$(MAKE) -C arch/$(target_os)/$(target_cpu) clean

distclean-local:
	$(MAKE) -C arch/$(target_os)/$(target_cpu) distclean

bin_PROGRAMS=fakeroot-ng
man1_MANS = fakeroot-ng.man

fakeroot_ng_DEPENDENCIES=build_lib
fakeroot_ng_SOURCES=main.cpp parent.h parent.cpp syscalls.h process.cpp file.cpp file_lie.cpp
#fakeroot_ng_LDFLAGS=-Larch/$(target_os)/$(target_cpu)
fakeroot_ng_LDADD=arch/$(target_os)/$(target_cpu)/libarch.la
fakeroot_ng_CPPFLAGS=-I$(top_srcdir)/arch/$(target_os)/$(target_cpu)
