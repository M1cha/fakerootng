ACLOCAL_AMFLAGS = -I m4

SUBDIRS=arch tests . unit_tests

clean-local:
	$(MAKE) -C arch/$(target_os)/$(target_cpu) clean

distclean-local:
	$(MAKE) -C arch/$(target_os)/$(target_cpu) distclean

bin_PROGRAMS=fakeroot-ng
man1_MANS = fakeroot-ng.man

fakeroot_ng_SOURCES=main.cpp log.cpp daemon.cpp worker_queue.cpp file_lie.cpp parent.cpp credentials.cpp process.cpp \
                    file.cpp memory.cpp input_stream.cpp lockless_event.cpp proxy_function.cpp
# ptrace.cpp chroot.cpp

#fakeroot_ng_LDFLAGS=-Larch/$(target_os)/$(target_cpu)
fakeroot_ng_LDADD=$(BOOST_LIBS) arch/$(target_os)/$(target_cpu)/libarch.a
fakeroot_ng_CPPFLAGS=-I$(top_srcdir)/arch/$(target_os)/$(target_cpu)
