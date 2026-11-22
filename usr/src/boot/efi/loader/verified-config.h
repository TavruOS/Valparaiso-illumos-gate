/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy is also available at http://www.illumos.org/license/CDDL.
 */

extern int valparaiso_check_manifest(const void *, size_t, const void *,
    size_t);
extern int valparaiso_check_boot_file(const void *, size_t, const char *,
    const void *, size_t);

struct verified_startup_file {
	const char *path;
	size_t length;
	unsigned char bytes[64 * 1024 + 1];
};

static struct verified_startup_file verified_startup_files[] = {
	{ .path = "/boot/loader.rc" },
	{ .path = "/boot/defaults/loader.conf" },
	{ .path = "/boot/loader.conf" }
};

static struct verified_startup_file *
verified_config_find(const char *path)
{
	for (size_t i = 0; i < sizeof (verified_startup_files) /
	    sizeof (verified_startup_files[0]); i++) {
		if (strcmp(path, verified_startup_files[i].path) == 0)
			return (&verified_startup_files[i]);
	}
	return (NULL);
}

static int
verified_config_open(const char *path, struct open_file *file)
{
	if (file->f_flags != (F_READ | F_NODEV))
		return (EACCES);
	file->f_fsdata = verified_config_find(path);
	return (file->f_fsdata != NULL ? 0 : ENOENT);
}

static int
verified_config_read(struct open_file *file, void *buffer, size_t size,
    size_t *resid)
{
	const struct verified_startup_file *snapshot = file->f_fsdata;
	size_t count = snapshot->length - (size_t)file->f_offset;

	if (count > size)
		count = size;
	bcopy(snapshot->bytes + file->f_offset, buffer, count);
	file->f_offset += count;
	*resid = size - count;
	return (0);
}

static off_t
verified_config_seek(struct open_file *file, off_t offset, int where)
{
	const struct verified_startup_file *snapshot = file->f_fsdata;
	off_t base;
	off_t length = snapshot->length;

	switch (where) {
	case SEEK_SET:
		base = 0;
		break;
	case SEEK_CUR:
		base = file->f_offset;
		break;
	case SEEK_END:
		base = length;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}
	if (offset < -base || offset > length - base) {
		errno = EINVAL;
		return (-1);
	}
	return (file->f_offset = base + offset);
}

static int
verified_config_stat(struct open_file *file, struct stat *st)
{
	const struct verified_startup_file *snapshot = file->f_fsdata;

	bzero(st, sizeof (*st));
	st->st_mode = S_IFREG | 0444;
	st->st_size = snapshot->length;
	return (0);
}

static struct fs_ops verified_config_ops = {
	.fs_name = "verified-config",
	.fo_open = verified_config_open,
	.fo_close = null_close,
	.fo_read = verified_config_read,
	.fo_write = null_write,
	.fo_seek = verified_config_seek,
	.fo_stat = verified_config_stat,
	.fo_readdir = null_readdir
};

static struct fs_ops *
verified_config_override(const char *path)
{
	if (verified_config_find(path) != NULL)
		return (&verified_config_ops);
	return (NULL);
}

static ssize_t
verified_config_read_file(const char *path, unsigned char *buffer, size_t limit)
{
	int fd = open(path, O_RDONLY | F_GZIP);
	size_t length = 0;
	ssize_t count;

	if (fd == -1)
		return (-1);
	while (length < limit) {
		count = read(fd, buffer + length, limit - length);
		if (count < 0) {
			(void) close(fd);
			return (-1);
		}
		if (count == 0)
			break;
		length += count;
	}
	(void) close(fd);
	return (length == limit ? -1 : (ssize_t)length);
}

static bool
verified_config_init(void)
{
	static unsigned char manifest[64 * 1024 + 1];
	static unsigned char signature[3309 + 1];
	ssize_t mlen, slen;

	mlen = verified_config_read_file("/boot.manifest", manifest,
	    sizeof (manifest));
	slen = verified_config_read_file("/boot.manifest.sig", signature,
	    sizeof (signature));
	if (mlen < 0 || slen < 0 ||
	    !valparaiso_check_manifest(manifest, mlen, signature, slen))
		return (false);

	for (size_t i = 0; i < sizeof (verified_startup_files) /
	    sizeof (verified_startup_files[0]); i++) {
		struct verified_startup_file *snapshot =
		    &verified_startup_files[i];
		ssize_t length = verified_config_read_file(snapshot->path,
		    snapshot->bytes, sizeof (snapshot->bytes));

		if (length < 0 || !valparaiso_check_boot_file(manifest, mlen,
		    snapshot->path + 1, snapshot->bytes, length)) {
			printf("Valparaiso: rejected %s\n", snapshot->path);
			return (false);
		}
		snapshot->length = length;
	}

	stand_file_override = verified_config_override;
	return (true);
}
