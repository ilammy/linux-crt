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

#include "syscall.h"

#include <stdio.h>
#include <stdint.h>

#include "procfs.h"

unsigned long find_syscall_instruction(struct library *library)
{
	for (size_t i = 0; i < library->region_count; i++) {
		struct memory_region *region = &library->regions[i];

		if (!(region->readable && region->executable))
			continue;

		const uint8_t *region_data = region->content;
		size_t region_size = region->vaddr_high - region->vaddr_low;

		if (region_size < 2)
			continue;

		for (size_t offset = 0; offset < region_size - 1; offset++) {
			if (region_data[offset + 0] == 0x0F &&
			    region_data[offset + 1] == 0x05)
			{
				return region->vaddr_low + offset;
			}
		}
	}

	fprintf(stderr, "[*] can't find a SYSCALL instruction\n");

	return 0;
}
