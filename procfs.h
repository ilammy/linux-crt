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

#ifndef LINUX_CRT_PROCFS_H
#define LINUX_CRT_PROCFS_H

#include <stdbool.h>
#include <sys/types.h>

/**
 * struct memory_region - mapped memory region of another process
 * @vaddr_low:  virtual address of the first byte of the region (inclusive)
 * @vaddr_high: virtual address of the last byte of the region (exclusive)
 * @readable:   region mapped as readable in another process
 * @writeable:  region mapped as writeable in another process 
 * @executable: region mapped as executable in another process
 * @content:    pointer to the read-only mapping of that memory
 *              in the current process
 */
struct memory_region {
	unsigned long vaddr_low;
	unsigned long vaddr_high;
	bool readable;
	bool writeable;
	bool executable;
	const void *content;
};

/**
 * struct library - mapped library of another process
 * @regions:      mapped regions of the library
 * @region_count: number of mapped regions
 */
struct library {
	struct memory_region *regions;
	size_t region_count;
};

/**
 * map_remote_library() - map a library of another process into current one
 * @pid:          PID of the remote process
 * @library_name: name of the library to remap
 * @library_map:  mapped library will be stored here
 *
 * Returns: zero on success, negative value on error.
 */
int map_remote_library(pid_t pid, const char *library_name,
		struct library *library_map);

/**
 * unmap_remote_library() - free previously mapped library
 * @library_map: mapping to free
 */
void unmap_remote_library(struct library *library_map);

/**
 * write_remote_memory() - write remote process memory
 * @pid:   PID of the remote process
 * @vaddr: virtual address in the remote process
 * @data:  local buffer to write
 * @size:  size of the buffer to write
 *
 * The remote process must be traced and stopped for this to work.
 *
 * Returns: zero on success, negative value on error.
 */
int write_remote_memory(pid_t pid, unsigned long vaddr,
		const void *data, size_t size);

#endif /* LINUX_CRT_PROCFS_H */
