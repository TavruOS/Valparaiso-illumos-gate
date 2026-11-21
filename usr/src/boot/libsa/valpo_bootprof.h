/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/* Temporary AMD64 loader profiling for Valparaiso QA. */
#ifndef VALPO_BOOTPROF_H
#define	VALPO_BOOTPROF_H
#if defined(__amd64)
extern int valpo_prof_active;
extern uint64_t valpo_prof_io, valpo_prof_io_bytes, valpo_prof_io_calls;
extern uint64_t valpo_prof_gzip, valpo_prof_zfs, valpo_prof_checksum;
static inline uint64_t
valpo_prof_ticks(void)
{
	uint32_t low, high;

	__asm__ __volatile__("lfence; rdtsc" : "=a" (low), "=d" (high) ::
	    "memory");
	return (((uint64_t)high << 32) | low);
}
#endif
#endif
