SUBDIRS=arch/linux/i386

bin_PROGRAMS=fakeroot-ng

fakeroot_ng_SOURCES=main.c parent.h parent.c platform.h
fakeroot_ng_LDFLAGS=-L$(srcdir)/arch/$(target_os)/$(target_cpu)
