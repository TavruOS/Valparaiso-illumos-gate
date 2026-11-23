#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

# Copyright 2015, Richard Lowe.


include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

PROG =	secflags_aslr		\
	secflags_core		\
	secflags_dts		\
	secflags_elfdump	\
	secflags_forbidnullmap	\
	secflags_limits		\
	secflags_noexecstack	\
	secflags_pie_heap	\
	secflags_proc		\
	secflags_psecflags	\
	secflags_syscall	\
	secflags_truss		\
	secflags_zonecfg

PROG += addrs-32 addrs-64 pie_heap stacky

ROOTOPTPKG = $(ROOT)/opt/os-tests
TESTDIR = $(ROOTOPTPKG)/tests/secflags

CMDS = $(PROG:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

CLEANFILES= stacky.o

addrs-32: addrs.c
	$(LINK.c) addrs.c -o $@ $(LDLIBS)
	$(POST_PROCESS)

addrs-64: addrs.c
	$(LINK64.c) addrs.c -o $@ $(LDLIBS64)
	$(POST_PROCESS)

stacky := MAPFILE.NES=			# Will foil the test, clearly
stacky: stacky.o
	$(LINK.c) stacky.o -o $@ $(LDLIBS)
	$(POST_PROCESS)

secflags_syscall: secflags_syscall.c
	$(LINK.c) secflags_syscall.c -o $@ $(LDLIBS)
	$(POST_PROCESS)

# Building a dynamic PIE requires the GNU link editor.
pie_heap: pie_heap.c
	LD_ALTEXEC=/usr/bin/gld $(CC) $(CFLAGS64) -fPIE -pie pie_heap.c -o $@
	$(POST_PROCESS)

all: $(PROG)

install: all $(CMDS)

lint:

clobber: clean
	-$(RM) $(PROG)

clean:
	-$(RM) $(CLEANFILES)

$(CMDS): $(TESTDIR) $(PROG)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)
