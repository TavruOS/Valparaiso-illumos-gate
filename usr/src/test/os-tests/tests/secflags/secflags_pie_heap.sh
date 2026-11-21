#! /usr/bin/ksh
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

set -e
cd "$(dirname "$0")"

# Exercise the first brk and malloc under libc and libumem in both modes.
for flags in none forbidnullmap; do
	mode=unprotected
	[[ $flags != forbidnullmap ]] || mode=protected
	/usr/bin/psecflags -s "$flags" -e ./pie_heap "$mode"
	/usr/bin/psecflags -s "$flags" -e /usr/bin/env \
	    LD_PRELOAD_64=libumem.so.1 ./pie_heap "$mode"
done

first=$(/usr/bin/psecflags -s aslr,forbidnullmap -e ./pie_heap protected)
for ((i = 0; i < 16; i++)); do
	next=$(/usr/bin/psecflags -s aslr,forbidnullmap -e ./pie_heap protected)
	[[ $first == "$next" ]] || exit 0
done

print -u2 "PIE heap did not move with ASLR and forbidnullmap enabled"
exit 1
