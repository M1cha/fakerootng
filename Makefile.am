SUBDIRS=arch/linux/i386

bin_PROGRAMS=fakeroot-ng

fakeroot_ng_SOURCES=main.cpp parent.h parent.cpp
#fakeroot_ng_LDFLAGS=-Larch/$(target_os)/$(target_cpu)
fakeroot_ng_LDADD=arch/$(target_os)/$(target_cpu)/libarch.la
