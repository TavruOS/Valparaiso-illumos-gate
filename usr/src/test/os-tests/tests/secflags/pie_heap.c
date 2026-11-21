/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	const size_t growth = 64 * 1024;
	const uintptr_t floor = 0x10000;
	unsigned char *base = sbrk(0);
	volatile unsigned char *allocation;
	void *buffer;

	if (base == (void *)-1)
		err(1, "sbrk(0)");
	if (argc != 2)
		errx(1, "expected a secflag mode");
	if (strcmp(argv[1], "protected") == 0 && (uintptr_t)base <= floor)
		errx(1, "heap %p is inside the protected null range",
		    (void *)base);

	if (brk(base + growth) != 0)
		err(1, "first brk");
	if (sbrk(0) != base + growth)
		errx(1, "unexpected break after growth");

	allocation = base;
	allocation[0] = 0x5a;
	allocation[growth - 1] = 0xa5;

	buffer = malloc(growth);
	if (buffer == NULL)
		err(1, "malloc");
	allocation = buffer;
	allocation[0] = 0x5a;
	allocation[growth - 1] = 0xa5;
	free(buffer);

	(void) printf("%p\n", (void *)base);
	return (0);
}
