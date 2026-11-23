/*
 * Copyright (c) 2018 Stormshield.
 * Copyright (c) 2018 Semihalf.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * TPM 2.0 driver for the Command Response Buffer (CRB) interface.
 *
 * Ported from FreeBSD sys/dev/tpm/tpm20.c and tpm_crb.c. This driver binds
 * to the ACPI MSFT0101 device and supports the plain CRB start method and
 * the CRB start method with an ACPI _DSM doorbell, which together cover
 * most firmware TPMs (Intel PTT, AMD fTPM) and the bhyve TPM emulation.
 * TIS/FIFO and Pluton start methods are not supported yet.
 *
 * /dev/tpm0 behaves like the FreeBSD and Linux raw TPM device: write(2)
 * one complete command, then read(2) its response, whole or in parts.
 * write(2) returns once the response is ready, so poll(2) reports POLLIN
 * while unread response bytes remain and POLLOUT at all times. The device
 * is opened exclusively; there is no in-kernel resource manager. All I/O
 * polls the hardware, as the FreeBSD driver does: CRB interrupts are
 * disabled.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/atomic.h>
#include <sys/byteorder.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>

/* Timeouts in microseconds (TCG PC Client PTP). */
#define	TPM2_TIMEOUT_A		750000
#define	TPM2_TIMEOUT_B		2000000
#define	TPM2_TIMEOUT_C		200000
/* Key generation can take far longer than any timeout in the spec. */
#define	TPM2_TIMEOUT_LONG	40000000

#define	TPM2_CC_CreatePrimary		0x00000131
#define	TPM2_CC_Create			0x00000153
#define	TPM2_CC_CreateLoaded		0x00000191
#define	TPM2_CC_SequenceComplete	0x0000013e
#define	TPM2_CC_Startup			0x00000144
#define	TPM2_CC_SequenceUpdate		0x0000015c
#define	TPM2_CC_GetCapability		0x0000017a
#define	TPM2_CC_PCR_Extend		0x00000182
#define	TPM2_CC_EventSequenceComplete	0x00000185
#define	TPM2_CC_HashSequenceStart	0x00000186

#define	TPM2_BUFSIZE		0x1000
#define	TPM2_HEADER_SIZE	10

/*
 * PTP locality registers, which precede the control area for the plain CRB
 * start method. TCG PC Client PTP 1.03, section 5.5.3.1, Table 23.
 */
#define	TPM2_LOC_STATE		0x00
#define	TPM2_LOC_CTRL		0x08
#define	TPM2_LOC_STS		0x0c
#define	TPM2_CRB_INTF_ID	0x30
#define	TPM2_LOC_SIZE		0x40

/* Control area registers, relative to ControlAddress in the TPM2 table. */
#define	TPM2_CRB_CTRL_REQ	0x00
#define	TPM2_CRB_CTRL_STS	0x04
#define	TPM2_CRB_CTRL_CANCEL	0x08
#define	TPM2_CRB_CTRL_START	0x0c
#define	TPM2_CRB_INT_ENABLE	0x10
#define	TPM2_CRB_CTRL_CMD_SIZE	0x18
#define	TPM2_CRB_CTRL_CMD_LADDR	0x1c
#define	TPM2_CRB_CTRL_CMD_HADDR	0x20
#define	TPM2_CRB_CTRL_RSP_SIZE	0x24
#define	TPM2_CRB_CTRL_RSP_LADDR	0x28
#define	TPM2_CRB_CTRL_RSP_HADDR	0x2c
#define	TPM2_CRB_CTRL_SIZE	0x30

#define	TPM2_LOC_STATE_ASSIGNED	(1U << 1)
#define	TPM2_LOC_STATE_VALID	(1U << 7)
#define	TPM2_LOC_CTRL_REQUEST	(1U << 0)
#define	TPM2_LOC_CTRL_RELINQUISH	(1U << 1)
#define	TPM2_CRB_REQ_GO_READY	(1U << 0)
#define	TPM2_CRB_REQ_GO_IDLE	(1U << 1)
#define	TPM2_CRB_STS_ERROR	(1U << 0)
#define	TPM2_CRB_STS_IDLE	(1U << 1)
#define	TPM2_CRB_CANCEL_CMD	0x1
#define	TPM2_CRB_CANCEL_CLEAR	0x0
#define	TPM2_CRB_START_CMD	(1U << 0)
#define	TPM2_CRB_INT_ENABLE_BIT	(1U << 31)

/* TCG ACPI 1.4, section 4.1: the CRB _DSM start method. */
#define	TPM2_DSM_REV		0
#define	TPM2_DSM_FUNC_QUERY	0
#define	TPM2_DSM_FUNC_START	1

/* 6BBF6CAB-5463-4714-B7CD-F0203C0368D4 */
static const uint8_t tpm2_dsm_uuid[16] = {
	0xab, 0x6c, 0xbf, 0x6b, 0x63, 0x54, 0x14, 0x47,
	0xb7, 0xcd, 0xf0, 0x20, 0x3c, 0x03, 0x68, 0xd4
};

typedef struct tpm2_map {
	caddr_t		tm_va;
	size_t		tm_size;
} tpm2_map_t;

typedef struct tpm2 {
	dev_info_t	*t_dip;
	kmutex_t	t_lock;		/* Serializes all device access. */
	boolean_t	t_open;
	boolean_t	t_acpi_start;	/* Ring the _DSM doorbell. */
	ACPI_HANDLE	t_acpi;
	boolean_t	t_has_locality;
	tpm2_map_t	t_loc;
	tpm2_map_t	t_ctrl;
	tpm2_map_t	t_cmd;
	tpm2_map_t	t_rsp;
	boolean_t	t_rsp_shared;
	struct pollhead	t_pollhead;
	size_t		t_len;		/* Unread response bytes. */
	size_t		t_off;
	uint8_t		t_buf[TPM2_BUFSIZE];
} tpm2_t;

static void *tpm2_statep;

static uint32_t
tpm2_rd(const tpm2_map_t *m, size_t off)
{
	return (*(volatile uint32_t *)(m->tm_va + off));
}

static void
tpm2_wr(const tpm2_map_t *m, size_t off, uint32_t val)
{
	*(volatile uint32_t *)(m->tm_va + off) = val;
	membar_producer();
}

/*
 * Poll until (reg & mask) == val. Always read once more after the last
 * delay, so a change during it is not reported as a timeout.
 */
static boolean_t
tpm2_wait(const tpm2_map_t *m, size_t off, uint32_t mask, uint32_t val,
    int64_t timeout)
{
	clock_t tick = drv_hztousec(1);

	for (;;) {
		if ((tpm2_rd(m, off) & mask) == val)
			return (B_TRUE);
		if (timeout <= 0)
			return (B_FALSE);
		delay(1);
		timeout -= tick;
	}
}

static int
tpm2_map(tpm2_map_t *m, uint64_t pa, size_t size)
{
	if (pa == 0 || size == 0 || pa + size < pa)
		return (EINVAL);
	m->tm_va = AcpiOsMapMemory(pa, size);
	if (m->tm_va == NULL)
		return (ENOMEM);
	m->tm_size = size;
	return (0);
}

static void
tpm2_unmap(tpm2_map_t *m)
{
	if (m->tm_va != NULL)
		AcpiOsUnmapMemory(m->tm_va, m->tm_size);
	m->tm_va = NULL;
	m->tm_size = 0;
}

static uint32_t
tpm2_timeout(uint32_t command)
{
	switch (command) {
	case TPM2_CC_CreatePrimary:
	case TPM2_CC_Create:
	case TPM2_CC_CreateLoaded:
		return (TPM2_TIMEOUT_LONG);
	case TPM2_CC_SequenceComplete:
	case TPM2_CC_Startup:
	case TPM2_CC_SequenceUpdate:
	case TPM2_CC_GetCapability:
	case TPM2_CC_PCR_Extend:
	case TPM2_CC_EventSequenceComplete:
	case TPM2_CC_HashSequenceStart:
		return (TPM2_TIMEOUT_C);
	default:
		return (TPM2_TIMEOUT_B);
	}
}

/* Evaluate the TPM start _DSM. The caller frees out->Pointer. */
static ACPI_STATUS
tpm2_dsm(tpm2_t *t, uint64_t func, ACPI_BUFFER *out)
{
	uint8_t uuid[sizeof (tpm2_dsm_uuid)];
	ACPI_OBJECT args[4];
	ACPI_OBJECT_LIST list;

	bcopy(tpm2_dsm_uuid, uuid, sizeof (uuid));
	args[0].Type = ACPI_TYPE_BUFFER;
	args[0].Buffer.Length = sizeof (uuid);
	args[0].Buffer.Pointer = uuid;
	args[1].Type = ACPI_TYPE_INTEGER;
	args[1].Integer.Value = TPM2_DSM_REV;
	args[2].Type = ACPI_TYPE_INTEGER;
	args[2].Integer.Value = func;
	args[3].Type = ACPI_TYPE_PACKAGE;
	args[3].Package.Count = 0;
	args[3].Package.Elements = NULL;
	list.Count = 4;
	list.Pointer = args;
	out->Length = ACPI_ALLOCATE_BUFFER;
	out->Pointer = NULL;
	return (AcpiEvaluateObject(t->t_acpi, "_DSM", &list, out));
}

static boolean_t
tpm2_acpi_start_supported(tpm2_t *t)
{
	ACPI_BUFFER buf;
	ACPI_OBJECT *obj;
	boolean_t ok = B_FALSE;

	if (ACPI_FAILURE(acpica_get_handle(t->t_dip, &t->t_acpi)))
		return (B_FALSE);
	if (ACPI_FAILURE(tpm2_dsm(t, TPM2_DSM_FUNC_QUERY, &buf)))
		return (B_FALSE);
	obj = buf.Pointer;
	if (obj != NULL && obj->Type == ACPI_TYPE_BUFFER &&
	    obj->Buffer.Length > 0 &&
	    (obj->Buffer.Pointer[0] & (1 << TPM2_DSM_FUNC_START)) != 0)
		ok = B_TRUE;
	AcpiOsFree(buf.Pointer);
	return (ok);
}

static boolean_t
tpm2_acpi_start(tpm2_t *t)
{
	ACPI_BUFFER buf;
	ACPI_OBJECT *obj;
	boolean_t ok;

	if (!t->t_acpi_start)
		return (B_TRUE);
	if (ACPI_FAILURE(tpm2_dsm(t, TPM2_DSM_FUNC_START, &buf))) {
		dev_err(t->t_dip, CE_WARN, "!ACPI start method failed");
		return (B_FALSE);
	}
	obj = buf.Pointer;
	ok = obj != NULL && obj->Type == ACPI_TYPE_INTEGER &&
	    obj->Integer.Value == 0;
	AcpiOsFree(buf.Pointer);
	return (ok);
}

static boolean_t
tpm2_request_locality(tpm2_t *t)
{
	const uint32_t mask = TPM2_LOC_STATE_VALID | TPM2_LOC_STATE_ASSIGNED;

	if (!t->t_has_locality)
		return (B_TRUE);
	tpm2_wr(&t->t_loc, TPM2_LOC_CTRL, TPM2_LOC_CTRL_REQUEST);
	return (tpm2_wait(&t->t_loc, TPM2_LOC_STATE, mask, mask,
	    TPM2_TIMEOUT_C));
}

static void
tpm2_relinquish_locality(tpm2_t *t)
{
	const uint32_t mask = TPM2_LOC_STATE_VALID | TPM2_LOC_STATE_ASSIGNED;

	if (!t->t_has_locality)
		return;
	tpm2_wr(&t->t_loc, TPM2_LOC_CTRL, TPM2_LOC_CTRL_RELINQUISH);
	if (!tpm2_wait(&t->t_loc, TPM2_LOC_STATE, mask, TPM2_LOC_STATE_VALID,
	    TPM2_TIMEOUT_C))
		dev_err(t->t_dip, CE_WARN, "!failed to relinquish locality");
}

/*
 * The ACPI start method has no idle or ready handshake: some firmware never
 * acknowledges CTRL_REQ. PTP 1.03, 5.5.3.4: the TPM clears the request bit
 * to acknowledge a state change.
 */
static boolean_t
tpm2_set_state(tpm2_t *t, uint32_t req)
{
	if (t->t_acpi_start)
		return (B_TRUE);
	tpm2_wr(&t->t_ctrl, TPM2_CRB_CTRL_REQ, req);
	return (tpm2_wait(&t->t_ctrl, TPM2_CRB_CTRL_REQ, req, 0,
	    TPM2_TIMEOUT_C));
}

static boolean_t
tpm2_cancel(tpm2_t *t)
{
	tpm2_wr(&t->t_ctrl, TPM2_CRB_CTRL_CANCEL, TPM2_CRB_CANCEL_CMD);
	(void) tpm2_acpi_start(t);
	if (!tpm2_wait(&t->t_ctrl, TPM2_CRB_CTRL_START, TPM2_CRB_START_CMD, 0,
	    TPM2_TIMEOUT_B)) {
		dev_err(t->t_dip, CE_WARN, "!device failed to cancel command");
		return (B_FALSE);
	}
	tpm2_wr(&t->t_ctrl, TPM2_CRB_CTRL_CANCEL, TPM2_CRB_CANCEL_CLEAR);
	return (B_TRUE);
}

static void
tpm2_copyout(const tpm2_map_t *m, uint8_t *dst, size_t off, size_t len)
{
	const volatile uint8_t *src = (const volatile uint8_t *)m->tm_va;

	for (size_t i = 0; i < len; i++)
		dst[i] = src[off + i];
}

static void
tpm2_copyin(const tpm2_map_t *m, const uint8_t *src, size_t len)
{
	volatile uint8_t *dst = (volatile uint8_t *)m->tm_va;

	for (size_t i = 0; i < len; i++)
		dst[i] = src[i];
	membar_producer();
}

/* Send the command in t_buf and leave the response there. */
static int
tpm2_transmit(tpm2_t *t, size_t length)
{
	uint32_t command, timeout, size;
	boolean_t started = B_FALSE;
	int error;

	ASSERT(MUTEX_HELD(&t->t_lock));

	if (length > t->t_cmd.tm_size)
		return (E2BIG);
	if (!tpm2_request_locality(t)) {
		dev_err(t->t_dip, CE_WARN, "!failed to obtain locality");
		return (EIO);
	}

	/* Meaningful only once the locality is ours. */
	if (tpm2_rd(&t->t_ctrl, TPM2_CRB_CTRL_STS) & TPM2_CRB_STS_ERROR) {
		dev_err(t->t_dip, CE_WARN, "!device has the error bit set");
		error = EIO;
		goto out;
	}
	tpm2_wr(&t->t_ctrl, TPM2_CRB_CTRL_CANCEL, TPM2_CRB_CANCEL_CLEAR);

	if ((tpm2_rd(&t->t_ctrl, TPM2_CRB_CTRL_STS) & TPM2_CRB_STS_IDLE) == 0 &&
	    !tpm2_set_state(t, TPM2_CRB_REQ_GO_IDLE)) {
		error = EIO;
		goto out;
	}
	if (!tpm2_set_state(t, TPM2_CRB_REQ_GO_READY)) {
		dev_err(t->t_dip, CE_WARN, "!failed to enter the ready state");
		error = EIO;
		goto out;
	}

	command = BE_IN32(&t->t_buf[6]);
	timeout = tpm2_timeout(command);

	tpm2_copyin(&t->t_cmd, t->t_buf, length);
	tpm2_wr(&t->t_ctrl, TPM2_CRB_CTRL_START, TPM2_CRB_START_CMD);
	started = B_TRUE;

	if (!tpm2_acpi_start(t) && !tpm2_cancel(t)) {
		error = EIO;
		goto out;
	}
	if (!tpm2_wait(&t->t_ctrl, TPM2_CRB_CTRL_START, TPM2_CRB_START_CMD, 0,
	    timeout)) {
		dev_err(t->t_dip, CE_WARN, "!timeout on command 0x%x",
		    command);
		if (!tpm2_cancel(t)) {
			error = EIO;
			goto out;
		}
	}
	if (tpm2_rd(&t->t_ctrl, TPM2_CRB_CTRL_STS) & TPM2_CRB_STS_ERROR) {
		dev_err(t->t_dip, CE_WARN, "!device error after command 0x%x",
		    command);
		error = EIO;
		goto out;
	}

	membar_consumer();
	tpm2_copyout(&t->t_rsp, t->t_buf, 0, TPM2_HEADER_SIZE);
	size = BE_IN32(&t->t_buf[2]);
	if (size < TPM2_HEADER_SIZE || size > t->t_rsp.tm_size) {
		dev_err(t->t_dip, CE_WARN, "!bad response size %u", size);
		error = EIO;
		goto out;
	}
	tpm2_copyout(&t->t_rsp, t->t_buf + TPM2_HEADER_SIZE, TPM2_HEADER_SIZE,
	    size - TPM2_HEADER_SIZE);
	t->t_off = 0;
	t->t_len = size;
	error = 0;

out:
	if (error != 0 && started &&
	    (tpm2_rd(&t->t_ctrl, TPM2_CRB_CTRL_START) & TPM2_CRB_START_CMD))
		(void) tpm2_cancel(t);
	/* A completed response stays valid if going idle times out. */
	if (!tpm2_set_state(t, TPM2_CRB_REQ_GO_IDLE))
		dev_err(t->t_dip, CE_WARN, "!failed to go idle after command");
	tpm2_relinquish_locality(t);
	return (error);
}

/* Plain CRB has locality registers in the 64 bytes before the control area. */
static boolean_t
tpm2_reg_has_locality(dev_info_t *dip, uint64_t ctrl)
{
	int *regs;
	uint_t n;
	boolean_t found = B_FALSE;

	if (ctrl < TPM2_LOC_SIZE ||
	    ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", &regs, &n) != DDI_PROP_SUCCESS)
		return (B_FALSE);
	/* ISA "reg" entries are (bustype, base, size); bustype 0 is memory. */
	for (uint_t i = 0; i + 2 < n; i += 3) {
		if (regs[i] == 0 &&
		    (uint64_t)(uint32_t)regs[i + 1] == ctrl - TPM2_LOC_SIZE &&
		    (uint32_t)regs[i + 2] >= TPM2_LOC_SIZE + TPM2_CRB_CTRL_SIZE)
			found = B_TRUE;
	}
	ddi_prop_free(regs);
	return (found);
}

static int
tpm2_setup(tpm2_t *t)
{
	ACPI_TABLE_TPM2 *tbl;
	uint64_t ctrl, cmd_addr, rsp_addr;
	uint32_t method, cmd_size, rsp_size, inten;
	int error;

	if (ACPI_FAILURE(AcpiGetTable(ACPI_SIG_TPM2, 1,
	    (ACPI_TABLE_HEADER **)(void *)&tbl)))
		return (ENXIO);
	if (tbl->Header.Length < sizeof (*tbl)) {
		AcpiPutTable((ACPI_TABLE_HEADER *)tbl);
		return (ENXIO);
	}
	ctrl = tbl->ControlAddress;
	method = tbl->StartMethod;
	AcpiPutTable((ACPI_TABLE_HEADER *)tbl);

	switch (method) {
	case ACPI_TPM2_COMMAND_BUFFER:
		t->t_has_locality = tpm2_reg_has_locality(t->t_dip, ctrl);
		break;
	case ACPI_TPM2_START_METHOD:
		if (!tpm2_acpi_start_supported(t)) {
			dev_err(t->t_dip, CE_WARN, "!no ACPI start method");
			return (ENXIO);
		}
		t->t_acpi_start = B_TRUE;
		break;
	default:
		dev_err(t->t_dip, CE_NOTE,
		    "!unsupported TPM2 start method %u", method);
		return (ENOTSUP);
	}

	if ((ctrl & 7) != 0 ||
	    tpm2_map(&t->t_ctrl, ctrl, TPM2_CRB_CTRL_SIZE) != 0) {
		dev_err(t->t_dip, CE_WARN, "!cannot map the CRB control area");
		return (ENXIO);
	}
	if (t->t_has_locality) {
		if (tpm2_map(&t->t_loc, ctrl - TPM2_LOC_SIZE,
		    TPM2_LOC_SIZE) != 0)
			return (ENXIO);
		/* Firmware can describe an absent TPM, e.g. with the ME off. */
		if (tpm2_rd(&t->t_loc, TPM2_CRB_INTF_ID) == UINT32_MAX) {
			dev_err(t->t_dip, CE_NOTE, "!no CRB interface present");
			return (ENXIO);
		}
	}

	if (!tpm2_request_locality(t)) {
		dev_err(t->t_dip, CE_WARN, "!failed to obtain locality");
		return (ENXIO);
	}
	if (!tpm2_set_state(t, TPM2_CRB_REQ_GO_READY)) {
		dev_err(t->t_dip, CE_WARN, "!failed to enter the ready state");
		error = ENXIO;
		goto out;
	}

	/* All I/O polls; disable CRB interrupts. */
	inten = tpm2_rd(&t->t_ctrl, TPM2_CRB_INT_ENABLE);
	tpm2_wr(&t->t_ctrl, TPM2_CRB_INT_ENABLE,
	    inten & ~TPM2_CRB_INT_ENABLE_BIT);

	/* PTP 1.03 requires naturally aligned 32-bit accesses here. */
	cmd_addr = tpm2_rd(&t->t_ctrl, TPM2_CRB_CTRL_CMD_LADDR) |
	    (uint64_t)tpm2_rd(&t->t_ctrl, TPM2_CRB_CTRL_CMD_HADDR) << 32;
	rsp_addr = tpm2_rd(&t->t_ctrl, TPM2_CRB_CTRL_RSP_LADDR) |
	    (uint64_t)tpm2_rd(&t->t_ctrl, TPM2_CRB_CTRL_RSP_HADDR) << 32;
	cmd_size = tpm2_rd(&t->t_ctrl, TPM2_CRB_CTRL_CMD_SIZE);
	rsp_size = tpm2_rd(&t->t_ctrl, TPM2_CRB_CTRL_RSP_SIZE);

	/* A shared buffer must report equal sizes (PTP 1.03, Table 23). */
	if (cmd_size < TPM2_HEADER_SIZE || rsp_size < TPM2_HEADER_SIZE ||
	    (cmd_addr == rsp_addr && cmd_size != rsp_size)) {
		dev_err(t->t_dip, CE_WARN, "!invalid CRB buffer sizes (%u, %u)",
		    cmd_size, rsp_size);
		error = ENXIO;
		goto out;
	}
	/* The device node never transfers more than TPM2_BUFSIZE bytes. */
	error = tpm2_map(&t->t_cmd, cmd_addr, MIN(cmd_size, TPM2_BUFSIZE));
	if (error != 0)
		goto out;
	if (cmd_addr == rsp_addr) {
		t->t_rsp = t->t_cmd;
		t->t_rsp_shared = B_TRUE;
	} else {
		error = tpm2_map(&t->t_rsp, rsp_addr,
		    MIN(rsp_size, TPM2_BUFSIZE));
	}

out:
	if (!tpm2_set_state(t, TPM2_CRB_REQ_GO_IDLE) && error == 0) {
		dev_err(t->t_dip, CE_WARN, "!failed to enter the idle state");
		error = ENXIO;
	}
	tpm2_relinquish_locality(t);
	return (error);
}

static void
tpm2_teardown(tpm2_t *t)
{
	if (t->t_rsp_shared)
		bzero(&t->t_rsp, sizeof (t->t_rsp));
	else
		tpm2_unmap(&t->t_rsp);
	tpm2_unmap(&t->t_cmd);
	tpm2_unmap(&t->t_ctrl);
	tpm2_unmap(&t->t_loc);
}

static int
tpm2_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	tpm2_t *t = ddi_get_soft_state(tpm2_statep, getminor(*devp));
	int error = 0;

	if (t == NULL)
		return (ENXIO);
	if (otyp != OTYP_CHR)
		return (EINVAL);
	if (drv_priv(credp) != 0)
		return (EPERM);
	if ((flag & (FREAD | FWRITE)) != (FREAD | FWRITE))
		return (EACCES);

	mutex_enter(&t->t_lock);
	if (t->t_open) {
		error = EBUSY;
	} else {
		t->t_open = B_TRUE;
		t->t_len = 0;
		t->t_off = 0;
	}
	mutex_exit(&t->t_lock);
	return (error);
}

static int
tpm2_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	tpm2_t *t = ddi_get_soft_state(tpm2_statep, getminor(dev));

	if (t == NULL)
		return (ENXIO);
	mutex_enter(&t->t_lock);
	t->t_open = B_FALSE;
	t->t_len = 0;
	t->t_off = 0;
	bzero(t->t_buf, sizeof (t->t_buf));
	mutex_exit(&t->t_lock);
	return (0);
}

static int
tpm2_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	tpm2_t *t = ddi_get_soft_state(tpm2_statep, getminor(dev));
	size_t n;
	int error;

	if (t == NULL)
		return (ENXIO);
	n = uiop->uio_resid;
	if (n < TPM2_HEADER_SIZE)
		return (EINVAL);
	if (n > TPM2_BUFSIZE)
		return (E2BIG);

	mutex_enter(&t->t_lock);
	t->t_len = 0;
	error = uiomove(t->t_buf, n, UIO_WRITE, uiop);
	/* The header must describe exactly one command of this size. */
	if (error == 0 && BE_IN32(&t->t_buf[2]) != n)
		error = EINVAL;
	if (error == 0)
		error = tpm2_transmit(t, n);
	mutex_exit(&t->t_lock);
	if (error == 0)
		pollwakeup(&t->t_pollhead, POLLIN | POLLRDNORM);
	return (error);
}

static int
tpm2_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	tpm2_t *t = ddi_get_soft_state(tpm2_statep, getminor(dev));
	short revents;

	if (t == NULL)
		return (ENXIO);
	revents = events & (POLLOUT | POLLWRNORM);
	mutex_enter(&t->t_lock);
	if (t->t_len > 0)
		revents |= events & (POLLIN | POLLRDNORM);
	mutex_exit(&t->t_lock);

	*reventsp = revents;
	if ((revents == 0 && !anyyet) || (events & POLLET) != 0)
		*phpp = &t->t_pollhead;
	return (0);
}

static int
tpm2_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	tpm2_t *t = ddi_get_soft_state(tpm2_statep, getminor(dev));
	size_t n;
	int error = 0;

	if (t == NULL)
		return (ENXIO);
	mutex_enter(&t->t_lock);
	n = MIN(t->t_len, uiop->uio_resid);
	if (n > 0) {
		error = uiomove(t->t_buf + t->t_off, n, UIO_READ, uiop);
		if (error == 0) {
			t->t_off += n;
			t->t_len -= n;
		}
	}
	mutex_exit(&t->t_lock);
	return (error);
}

static int
tpm2_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	char name[16];
	tpm2_t *t;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(tpm2_statep, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);
	t = ddi_get_soft_state(tpm2_statep, instance);
	t->t_dip = dip;
	mutex_init(&t->t_lock, NULL, MUTEX_DRIVER, NULL);

	if (tpm2_setup(t) != 0)
		goto fail;
	(void) snprintf(name, sizeof (name), "tpm%d", instance);
	if (ddi_create_minor_node(dip, name, S_IFCHR, instance,
	    DDI_PSEUDO, 0) != DDI_SUCCESS)
		goto fail;
	ddi_report_dev(dip);
	return (DDI_SUCCESS);

fail:
	tpm2_teardown(t);
	mutex_destroy(&t->t_lock);
	ddi_soft_state_free(tpm2_statep, instance);
	return (DDI_FAILURE);
}

static int
tpm2_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	tpm2_t *t = ddi_get_soft_state(tpm2_statep, instance);

	if (cmd != DDI_DETACH || t == NULL)
		return (DDI_FAILURE);
	mutex_enter(&t->t_lock);
	if (t->t_open) {
		mutex_exit(&t->t_lock);
		return (DDI_FAILURE);
	}
	mutex_exit(&t->t_lock);

	ddi_remove_minor_node(dip, NULL);
	pollhead_clean(&t->t_pollhead);
	tpm2_teardown(t);
	mutex_destroy(&t->t_lock);
	ddi_soft_state_free(tpm2_statep, instance);
	return (DDI_SUCCESS);
}

static int
tpm2_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	minor_t minor = getminor((dev_t)arg);
	tpm2_t *t;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		t = ddi_get_soft_state(tpm2_statep, minor);
		if (t == NULL)
			return (DDI_FAILURE);
		*resultp = t->t_dip;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)(uintptr_t)minor;
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static struct cb_ops tpm2_cb_ops = {
	.cb_open =	tpm2_open,
	.cb_close =	tpm2_close,
	.cb_strategy =	nodev,
	.cb_print =	nodev,
	.cb_dump =	nodev,
	.cb_read =	tpm2_read,
	.cb_write =	tpm2_write,
	.cb_ioctl =	nodev,
	.cb_devmap =	nodev,
	.cb_mmap =	nodev,
	.cb_segmap =	nodev,
	.cb_chpoll =	tpm2_chpoll,
	.cb_prop_op =	ddi_prop_op,
	.cb_str =	NULL,
	.cb_flag =	D_MP,
	.cb_rev =	CB_REV,
	.cb_aread =	nodev,
	.cb_awrite =	nodev
};

static struct dev_ops tpm2_dev_ops = {
	.devo_rev =		DEVO_REV,
	.devo_refcnt =		0,
	.devo_getinfo =		tpm2_getinfo,
	.devo_identify =	nulldev,
	.devo_probe =		nulldev,
	.devo_attach =		tpm2_attach,
	.devo_detach =		tpm2_detach,
	.devo_reset =		nodev,
	.devo_cb_ops =		&tpm2_cb_ops,
	.devo_bus_ops =		NULL,
	.devo_power =		NULL,
	.devo_quiesce =		ddi_quiesce_not_needed
};

static struct modldrv tpm2_modldrv = {
	&mod_driverops,
	"TPM 2.0 CRB driver",
	&tpm2_dev_ops
};

static struct modlinkage tpm2_modlinkage = {
	MODREV_1,
	{ &tpm2_modldrv, NULL }
};

int
_init(void)
{
	int error;

	if ((error = ddi_soft_state_init(&tpm2_statep, sizeof (tpm2_t),
	    1)) != 0)
		return (error);
	if ((error = mod_install(&tpm2_modlinkage)) != 0)
		ddi_soft_state_fini(&tpm2_statep);
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&tpm2_modlinkage, modinfop));
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&tpm2_modlinkage)) == 0)
		ddi_soft_state_fini(&tpm2_statep);
	return (error);
}
