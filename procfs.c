/*
 * CreateRemoteThread for Linux
 *
 * Copyright (c) 2018, ilammy
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 */

#include "procfs.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/uio.h>

static bool read_proc_line(const char *line, const char *library,
		struct memory_region *region)
{
	unsigned long vaddr_low = 0;
	unsigned long vaddr_high = 0;
	char read = 0;
	char write = 0;
	char execute = 0;
	int path_offset = 0;

	sscanf(line, "%lx-%lx %c%c%c%*c %*x %*x:%*x %*d %n",
		&vaddr_low, &vaddr_high, &read, &write, &execute,
		&path_offset);

	if (!strstr(line + path_offset, library))
		return false;

	if (region) {
		region->vaddr_low = vaddr_low;
		region->vaddr_high = vaddr_high;
		region->readable = (read == 'r');
		region->writeable = (write == 'w');
		region->executable = (execute == 'x');
		region->content = NULL;
	}

	return true;
}

static int resize_mapping(size_t new_count, struct library *mapping)
{
	size_t new_size = new_count * sizeof(struct memory_region);
	struct memory_region *new_regions =
		realloc(mapping->regions, new_size);

	if (!new_regions) {
		fprintf(stderr, "[*] failed to reallocate regions\n");
		return -1;
	}

	mapping->regions = new_regions;
	mapping->region_count = new_count;

	return 0;
}

static int do_read_mapping(FILE *fp, const char *library_name,
		struct library *library_mapping)
{
	size_t count = 0;
	char line[1024] = {0};

	while (fgets(line, sizeof(line), fp)) {
		if (count == library_mapping->region_count) {
			if (resize_mapping(2 * count, library_mapping) < 0)
				return -1;
		}

		struct memory_region *region = &library_mapping->regions[count];

		if (read_proc_line(line, library_name, region))
			count++;
	}

	if (ferror(fp)) {
		fprintf(stderr, "[*] failed to read procfs: %s\n",
			strerror(errno));
		return -1;
	}

	library_mapping->region_count = count;

	return 0;
}

static int read_mapping(pid_t pid, const char *library_name,
		struct library *library_mapping)
{
	char path[32];

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);

	FILE *fp = fopen(path, "r");
	if (!fp) {
		fprintf(stderr, "[*] failed to open %s: %s\n",
			path, strerror(errno));
		return -1;
	}

	int err = do_read_mapping(fp, library_name, library_mapping);

	if (fclose(fp)) {
		fprintf(stderr, "[!] failed to close %s: %s\n",
			path, strerror(errno));
	}

	return err;
}

/*
 * Despite names like 'map' and 'unmap', these functions do not actually
 * use mmap() and munmap(). This is because /proc/$pid/mem is not mappable.
 * Thus we have to malloc() some memory buffer and simply read the file.
 */

static int map_region(struct memory_region *region)
{
	size_t length = region->vaddr_high - region->vaddr_low;
	off_t offset = region->vaddr_low;

	void *buffer = malloc(length);
	if (!buffer) {
		fprintf(stderr, "[*] failed to allocate buffer (%zu bytes)\n",
			length);
		return -1;
	}

	printf("[.] reading %c%c%c region at %lx-%lx\n",
		region->readable ? 'r' : '-',
		region->writeable ? 'w' : '-',
		region->executable ? 'x' : '-',
		region->vaddr_low, region->vaddr_high);

	region->content = buffer;

	return 0;
}

static void unmap_region(struct memory_region *region)
{
	free((void*) region->content);
	region->content = NULL;
}

static int do_map_regions(pid_t pid, struct library *mapping,
		struct iovec *local_iov, struct iovec *remote_iov)
{
	size_t mapped;
	size_t read_bytes = 0;
	size_t total_bytes = 0;

	for (mapped = 0; mapped < mapping->region_count; mapped++) {
		struct memory_region *current = &mapping->regions[mapped];

		if (!current->readable) {
			printf("[.]  unreadable region at %lx-%lx\n",
				current->vaddr_low, current->vaddr_high);
			continue;
		}

		if (map_region(current) < 0)
			goto error_unmap;

		local_iov[mapped].iov_base = (void*)current->content;
		local_iov[mapped].iov_len = current->vaddr_high - current->vaddr_low;
		remote_iov[mapped].iov_base = (void*)current->vaddr_low;
		remote_iov[mapped].iov_len = current->vaddr_high - current->vaddr_low;
		total_bytes += current->vaddr_high - current->vaddr_low;
	}

	read_bytes = process_vm_readv(pid, local_iov, mapping->region_count,
		remote_iov, mapping->region_count, 0);

	if (read_bytes < 0) {
		fprintf(stderr, "[!] failed to read remote image: %s\n",
			strerror(errno));
		goto error_unmap;
	}
	if (read_bytes != total_bytes) {
		/*
		 * We could count the bytes, adjust local_iov and remote_iov, and
		 * continue reading but I'm too lazy for that. Treat it as an error.
		 */
		fprintf(stderr, "[*] partial read of remote image: (%zu/%zu bytes)\n",
			read_bytes, total_bytes);
		goto error_unmap;
	}

	return 0;

error_unmap:
	for (size_t i = 0; i < mapped; i++)
		unmap_region(&mapping->regions[mapped]);

	return -1;
}

static int map_regions(pid_t pid, struct library *mapping)
{
	int res = -1;
	struct iovec *local_iov = NULL;
	struct iovec *remote_iov = NULL;

	local_iov = calloc(mapping->region_count, sizeof(*local_iov));
	remote_iov = calloc(mapping->region_count, sizeof(*remote_iov));
	if (!local_iov || !remote_iov) {
		fprintf(stderr, "[*] failed to allocate %zu iovecs\n",
			mapping->region_count);
		goto error;
	}

	res = do_map_regions(pid, mapping, local_iov, remote_iov);

error:
	free(local_iov);
	free(remote_iov);

	return res;
}

int map_remote_library(pid_t pid, const char *library_name,
		struct library *library_map)
{
	/*
	 * Usually a library will have four memory regions:
	 * - executable text
	 * - padding region
	 * - read-only data
	 * - writeable data
	 */
	library_map->regions = calloc(4, sizeof(library_map->regions[0]));
	library_map->region_count = 4;

	if (!library_map->regions) {
		fprintf(stderr, "[*] failed to allocate memory regions\n");
		goto error;
	}

	if (read_mapping(pid, library_name, library_map) < 0)
		goto error_free;

	if (map_regions(pid, library_map) < 0)
		goto error_free;

	return 0;

error_free:
	free(library_map->regions);
error:
	library_map->regions = NULL;
	library_map->region_count = 0;

	return -1;
}

void unmap_remote_library(struct library *library_map)
{
	for (size_t i = 0; i < library_map->region_count; i++)
		unmap_region(&library_map->regions[i]);

	free(library_map->regions);

	library_map->regions = NULL;
	library_map->region_count = 0;
}

static int do_write_remote_memory(int fd, const void *data, size_t size)
{
	size_t remaining = size;

	while (remaining > 0) {
		ssize_t wrote = write(fd, data, remaining);

		if (wrote < 0) {
			fprintf(stderr, "[!] failed to write memory: %s\n",
				strerror(errno));
			return -1;
		}

		data += wrote;
		remaining -= wrote;
	}

	return 0;
}

int write_remote_memory(pid_t pid, unsigned long vaddr,
		const void *data, size_t size)
{
	int err = 0;
	char path[32] = {0};

	snprintf(path, sizeof(path), "/proc/%d/mem", pid);

	int fd = open(path, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "[*] failed to open %s: %s\n",
			path, strerror(errno));
		return -1;
	}

	if (lseek(fd, vaddr, SEEK_SET) < 0) {
		err = -1;
		fprintf(stderr, "[*] failed to seek to %ld: %s\n",
			vaddr, strerror(errno));
		goto error_close;
	}

	err = do_write_remote_memory(fd, data, size);

error_close:
	if (close(fd) < 0) {
		fprintf(stderr, "[!] failed to close %s (%d): %s\n",
			path, fd, strerror(errno));
	}

	return err;
}
