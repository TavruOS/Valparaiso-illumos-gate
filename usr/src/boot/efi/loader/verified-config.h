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
	unsigned char *bytes;
	EFI_PHYSICAL_ADDRESS address;
	UINTN pages;
	struct verified_startup_file *next;
};

static unsigned char verified_manifest[64 * 1024 + 1];
static size_t verified_manifest_length;
static bool opening_raw_startup_file;
static struct verified_startup_file *verified_fragments;

static ssize_t verified_config_read_file(const char *, unsigned char *, size_t);

#define	VERIFIED_CONFIG_LIMIT (64 * 1024)
#define	VERIFIED_KERNEL_LIMIT (16 * 1024 * 1024)
#define	VERIFIED_ARCHIVE_LIMIT (256 * 1024 * 1024)

static const char verified_archive_path[] =
	"/platform/i86pc/amd64/boot_archive";
static const char verified_archive_hash_path[] =
	"/platform/i86pc/amd64/boot_archive.hash";

static const char verified_kernel_path[] =
	"/platform/i86pc/kernel/amd64/unix";
static unsigned char verified_startup_bytes[3][VERIFIED_CONFIG_LIMIT + 1];
static struct verified_startup_file verified_startup_files[] = {
	{ .path = "/boot/loader.rc", .bytes = verified_startup_bytes[0] },
	{ .path = "/boot/defaults/loader.conf",
	    .bytes = verified_startup_bytes[1] },
	{ .path = "/boot/loader.conf", .bytes = verified_startup_bytes[2] }
};

static bool
verified_archive_allowed(const char *path)
{
	return (path != NULL && strcmp(path, verified_archive_path) == 0);
}

static bool
verified_raw_module_allowed(const char *path, const char *type)
{
	if (path == NULL || type == NULL)
		return (false);
	if (strcmp(type, "rootfs") == 0)
		return (verified_archive_allowed(path));
	return (strcmp(type, "hash") == 0 &&
	    strcmp(path, verified_archive_hash_path) == 0);
}

static bool
verified_kernel_allowed(const char *path)
{
	return (path != NULL && strcmp(path, verified_kernel_path) == 0);
}

/*
 * Refuse kernel flags that hand control of the booted system to the console:
 * -k loads kmdb, -d enters it before startup and -a prompts for an alternate
 * system file. Skip the property list that follows -B.
 */
#define	VERIFIED_ARG_END(c)	((c) == '\0' || (c) == ' ' || (c) == '\t')

static bool
verified_kernel_args_allowed(const char *args)
{
	const char *p = args;

	if (p == NULL)
		return (true);
	while (*p != '\0') {
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p != '-') {
			while (!VERIFIED_ARG_END(*p))
				p++;
			continue;
		}
		for (p++; !VERIFIED_ARG_END(*p); p++) {
			if (*p == 'B') {
				if (VERIFIED_ARG_END(p[1])) {
					p++;
					while (*p == ' ' || *p == '\t')
						p++;
				}
				while (!VERIFIED_ARG_END(*p))
					p++;
				break;
			}
			if (*p == 'k' || *p == 'd' || *p == 'a')
				return (false);
		}
	}
	return (true);
}

static struct verified_startup_file *
verified_config_find(const char *path)
{
	for (size_t i = 0; i < sizeof (verified_startup_files) /
	    sizeof (verified_startup_files[0]); i++) {
		if (strcmp(path, verified_startup_files[i].path) == 0)
			return (&verified_startup_files[i]);
	}
	for (struct verified_startup_file *fragment = verified_fragments;
	    fragment != NULL; fragment = fragment->next) {
		if (strcmp(path, fragment->path) == 0)
			return (fragment);
	}
	return (NULL);
}

static int
verified_config_open(const char *path, struct open_file *file)
{
	struct verified_startup_file *snapshot;
	ssize_t length;

	if (file->f_flags != (F_READ | F_NODEV))
		return (EACCES);

	snapshot = verified_config_find(path);
	if (snapshot == NULL) {
		size_t limit = verified_kernel_allowed(path) ?
		    VERIFIED_KERNEL_LIMIT : VERIFIED_CONFIG_LIMIT;

		snapshot = malloc(sizeof (*snapshot) + limit + 1);
		if (snapshot == NULL)
			return (ENOMEM);
		snapshot->bytes = (unsigned char *)(snapshot + 1);
		length = verified_config_read_file(path, snapshot->bytes,
		    limit + 1);
		if (length < 0) {
			int error = errno;

			free(snapshot);
			return (error);
		}
		if (!valparaiso_check_boot_file(verified_manifest,
		    verified_manifest_length, path + 1, snapshot->bytes,
		    length)) {
			printf("Valparaiso: rejected %s\n", path);
			free(snapshot);
			return (EAUTH);
		}
		snapshot->path = NULL;
		snapshot->pages = 0;
		snapshot->length = length;
	}

	file->f_fsdata = snapshot;
	return (0);
}

/*
 * Open the compressed archive for gzip. Allocate the snapshot outside the
 * standalone heap, which is too small for an installed boot archive.
 */
static int
verified_archive_raw_open(const char *path, struct open_file *file)
{
	struct verified_startup_file *snapshot;
	struct stat st;
	int fd;
	ssize_t count;
	size_t offset = 0;
	unsigned char extra;

	snapshot = calloc(1, sizeof (*snapshot));
	if (snapshot == NULL)
		return (EAUTH);

	opening_raw_startup_file = true;
	fd = open(path, O_RDONLY | F_GZIP);
	opening_raw_startup_file = false;
	if (fd == -1)
		goto fail;
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
	    st.st_size <= 0 || st.st_size > VERIFIED_ARCHIVE_LIMIT)
		goto fail;
	snapshot->length = st.st_size;
	snapshot->pages = EFI_SIZE_TO_PAGES(snapshot->length);
	snapshot->address = 0xffffffff;
	if (EFI_ERROR(BS->AllocatePages(AllocateMaxAddress, EfiLoaderData,
	    snapshot->pages, &snapshot->address))) {
		snapshot->pages = 0;
		goto fail;
	}
	snapshot->bytes = (unsigned char *)(uintptr_t)snapshot->address;
	while (offset < snapshot->length) {
		count = read(fd, snapshot->bytes + offset,
		    snapshot->length - offset);
		if (count <= 0)
			goto fail;
		offset += count;
	}
	if (read(fd, &extra, 1) != 0 ||
	    !valparaiso_check_boot_file(verified_manifest,
	    verified_manifest_length, path + 1, snapshot->bytes,
	    snapshot->length))
		goto fail;

	(void) close(fd);
	file->f_fsdata = snapshot;
	return (0);

fail:
	if (fd != -1)
		(void) close(fd);
	if (snapshot->pages != 0)
		(void) BS->FreePages(snapshot->address, snapshot->pages);
	free(snapshot);
	printf("Valparaiso: rejected %s\n", path);
	return (EAUTH);
}

static int
verified_archive_open(const char *path, struct open_file *file)
{
	int error;

	if (file->f_flags != (F_READ | F_NODEV))
		return (EACCES);
	file->f_flags = F_READ;
	error = gzipfs_fsops.fo_open(path, file);
	file->f_flags = F_READ | F_NODEV;
	return (error);
}

static int
verified_config_close(struct open_file *file)
{
	struct verified_startup_file *snapshot = file->f_fsdata;

	if (snapshot->pages != 0)
		(void) BS->FreePages(snapshot->address, snapshot->pages);
	if (snapshot->path == NULL)
		free(snapshot);
	return (0);
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
	.fo_close = verified_config_close,
	.fo_read = verified_config_read,
	.fo_write = null_write,
	.fo_seek = verified_config_seek,
	.fo_stat = verified_config_stat,
	.fo_readdir = null_readdir
};

/* Expose the authenticated fragment set as a read-only directory. */
static int
verified_confdir_open(const char *path __unused, struct open_file *file)
{
	if (file->f_flags != (F_READ | F_NODEV))
		return (EACCES);
	file->f_fsdata = verified_fragments;
	return (0);
}

static int
verified_confdir_stat(struct open_file *file __unused, struct stat *st)
{
	bzero(st, sizeof (*st));
	st->st_mode = S_IFDIR | 0555;
	return (0);
}

static const char verified_confdir_prefix[] = "/boot/conf.d/";

static bool
verified_optional_config(const char *path)
{
	return (strcmp(path, "/boot/menu.rc") == 0 ||
	    strcmp(path, "/boot/menu.rc.local") == 0 ||
	    strcmp(path, "/boot/loader.rc.local") == 0 ||
	    strcmp(path, "/boot/loader.conf.local") == 0 ||
	    strcmp(path, "/boot/solaris/bootenv.rc") == 0);
}

static int
verified_confdir_readdir(struct open_file *file, struct dirent *entry)
{
	const struct verified_startup_file *fragment = file->f_fsdata;
	const char *name;

	while (fragment != NULL && strncmp(fragment->path,
	    verified_confdir_prefix, sizeof (verified_confdir_prefix) - 1) != 0)
		fragment = fragment->next;
	if (fragment == NULL)
		return (ENOENT);
	name = fragment->path + sizeof (verified_confdir_prefix) - 1;
	bzero(entry, sizeof (*entry));
	(void) strlcpy(entry->d_name, name, sizeof (entry->d_name));
	entry->d_namlen = strlen(name);
	entry->d_type = DT_REG;
	file->f_fsdata = fragment->next;
	return (0);
}

static int
verified_file_denied(const char *path __unused,
    struct open_file *file __unused)
{
	return (EAUTH);
}

static struct fs_ops verified_confdir_ops = {
	.fs_name = "verified-confdir",
	.fo_open = verified_confdir_open,
	.fo_close = null_close,
	.fo_read = null_read,
	.fo_write = null_write,
	.fo_seek = null_seek,
	.fo_stat = verified_confdir_stat,
	.fo_readdir = verified_confdir_readdir
};

static struct fs_ops verified_denied_ops = {
	.fs_name = "verified-denied",
	.fo_open = verified_file_denied
};

static struct fs_ops verified_archive_raw_ops;
static struct fs_ops verified_archive_ops;

static struct fs_ops *
verified_config_override(const char *path, int mode)
{
	if (opening_raw_startup_file)
		return (NULL);
	if (strcmp(path, "/boot/conf.d") == 0)
		return (&verified_confdir_ops);
	if (verified_archive_allowed(path))
		return (mode == (O_RDONLY | F_GZIP) ?
		    &verified_archive_raw_ops : &verified_archive_ops);
	if (verified_kernel_allowed(path) ||
	    strcmp(path, verified_archive_hash_path) == 0 ||
	    verified_config_find(path) != NULL ||
	    strncmp(path, "/boot/forth/", sizeof ("/boot/forth/") - 1) == 0 ||
	    strncmp(path, "/boot/defaults/",
	    sizeof ("/boot/defaults/") - 1) == 0)
		return (&verified_config_ops);
	return (&verified_denied_ops);
}

static ssize_t
verified_config_read_file(const char *path, unsigned char *buffer, size_t limit)
{
	size_t length = 0;
	ssize_t count;
	int fd;

	opening_raw_startup_file = true;
	fd = open(path, O_RDONLY | F_GZIP);
	opening_raw_startup_file = false;
	if (fd == -1)
		return (-1);
	while (length < limit) {
		count = read(fd, buffer + length, limit - length);
		if (count < 0) {
			int error = errno;

			(void) close(fd);
			errno = error;
			return (-1);
		}
		if (count == 0)
			break;
		length += count;
	}
	(void) close(fd);
	if (length == limit) {
		errno = EFBIG;
		return (-1);
	}
	return (length);
}

static bool
verified_firmware_enforcing(void)
{
	UINT8 secure_boot = 0, setup_mode = 1;
	size_t length = sizeof (secure_boot);

	if (EFI_ERROR(efi_global_getenv("SecureBoot", &secure_boot, &length)) ||
	    length != sizeof (secure_boot) || secure_boot != 1)
		return (false);
	length = sizeof (setup_mode);
	return (!EFI_ERROR(efi_global_getenv("SetupMode", &setup_mode,
	    &length)) && length == sizeof (setup_mode) && setup_mode == 0);
}

/*
 * The manifest has already passed signature and format validation. Pin each
 * listed config fragment and optional startup file before running Forth.
 */
static bool
verified_load_fragments(void)
{
	static unsigned char bytes[VERIFIED_CONFIG_LIMIT + 1];
	const char *row = (const char *)verified_manifest;
	const char *end = row + verified_manifest_length;
	const size_t prefix_length = sizeof (verified_confdir_prefix) - 2;
	struct verified_startup_file **next = &verified_fragments;
	const char *newline;

	newline = memchr(row, '\n', end - row);
	if (newline == NULL)
		return (false);
	for (row = newline + 1; row < end; row = newline + 1) {
		char path[sizeof (verified_confdir_prefix) + MAXNAMLEN];
		const char *name;
		size_t name_length;
		ssize_t length;
		struct verified_startup_file *fragment;

		newline = memchr(row, '\n', end - row);
		if (newline == NULL || newline - row < 66)
			goto fail;
		name = row + 66;
		name_length = newline - name;
		if (name_length >= sizeof (path) - 1) {
			if (strncmp(name, verified_confdir_prefix + 1,
			    prefix_length) == 0)
				goto fail;
			continue;
		}
		path[0] = '/';
		bcopy(name, path + 1, name_length);
		path[name_length + 1] = '\0';

		if (name_length > prefix_length &&
		    strncmp(name, verified_confdir_prefix + 1,
		    prefix_length) == 0) {
			name += prefix_length;
			name_length -= prefix_length;
			if (name_length > MAXNAMLEN ||
			    memchr(name, '/', name_length) != NULL)
				goto fail;
		} else if (!verified_optional_config(path)) {
			continue;
		}
		length = verified_config_read_file(path, bytes, sizeof (bytes));
		if (length < 0 || !valparaiso_check_boot_file(verified_manifest,
		    verified_manifest_length, path + 1, bytes, length)) {
			printf("Valparaiso: rejected %s\n", path);
			goto fail;
		}
		fragment = calloc(1, sizeof (*fragment) + strlen(path) + 1 +
		    length);
		if (fragment == NULL)
			goto fail;
		fragment->path = (char *)(fragment + 1);
		(void) strcpy((char *)fragment->path, path);
		fragment->length = length;
		fragment->bytes = (unsigned char *)fragment->path +
		    strlen(path) + 1;
		bcopy(bytes, fragment->bytes, length);
		*next = fragment;
		next = &fragment->next;
	}
	return (true);

fail:
	while (verified_fragments != NULL) {
		struct verified_startup_file *fragment = verified_fragments;

		verified_fragments = fragment->next;
		free(fragment);
	}
	return (false);
}

static bool
verified_config_init(void)
{
	static unsigned char signature[3309 + 1];
	ssize_t mlen, slen;

	mlen = verified_config_read_file("/boot.manifest", verified_manifest,
	    sizeof (verified_manifest));
	slen = verified_config_read_file("/boot.manifest.sig", signature,
	    sizeof (signature));
	if (mlen < 0 || slen < 0 ||
	    !valparaiso_check_manifest(verified_manifest, mlen, signature,
	    slen))
		return (false);

	for (size_t i = 0; i < sizeof (verified_startup_files) /
	    sizeof (verified_startup_files[0]); i++) {
		struct verified_startup_file *snapshot =
		    &verified_startup_files[i];
		ssize_t length = verified_config_read_file(snapshot->path,
		    snapshot->bytes, VERIFIED_CONFIG_LIMIT + 1);

		if (length < 0 || !valparaiso_check_boot_file(verified_manifest,
		    mlen, snapshot->path + 1, snapshot->bytes, length)) {
			printf("Valparaiso: rejected %s\n", snapshot->path);
			return (false);
		}
		snapshot->length = length;
	}

	verified_manifest_length = mlen;
	if (!verified_load_fragments())
		return (false);
	verified_archive_raw_ops = verified_config_ops;
	verified_archive_raw_ops.fo_open = verified_archive_raw_open;
	verified_archive_ops = gzipfs_fsops;
	verified_archive_ops.fo_open = verified_archive_open;
	stand_file_override = verified_config_override;
	archsw.arch_kernel_allowed = verified_kernel_allowed;
	archsw.arch_raw_module_allowed = verified_raw_module_allowed;
	archsw.arch_kernel_args_allowed = verified_kernel_args_allowed;
	return (true);
}
