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

#include "shell.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "inject-thread.h"
#include "procfs.h"
#include "shell_text.h"

static inline void copy_shellcode(char *shellcode_text,
		const char *shellcode_addr,
		const void *data, size_t length)
{
	ptrdiff_t offset = shellcode_addr - shellcode_start;
	memcpy(shellcode_text + offset, data, length);
}

static void prepare_shellcode(char *shellcode_text, size_t shellcode_size)
{
	copy_shellcode(shellcode_text, shellcode_start,
		shellcode_start, shellcode_size);

	copy_shellcode(shellcode_text, shellcode_address_dlopen,
		&dlopen_vaddr, sizeof(dlopen_vaddr));
	copy_shellcode(shellcode_text, shellcode_address_dlsym,
		&dlsym_vaddr, sizeof(dlsym_vaddr));
	copy_shellcode(shellcode_text, shellcode_address_pthread_create,
		&pthread_create_vaddr, sizeof(pthread_create_vaddr));
	copy_shellcode(shellcode_text, shellcode_address_pthread_detach,
		&pthread_detach_vaddr, sizeof(pthread_detach_vaddr));

	copy_shellcode(shellcode_text, shellcode_address_payload,
		payload, sizeof(payload));
	copy_shellcode(shellcode_text, shellcode_address_entry,
		entry, sizeof(entry));
}

int write_shellcode(void)
{
	int err = 0;
	char shellcode_text[SHELLCODE_TEXT_SIZE];
	size_t shellcode_size = shellcode_end - shellcode_start;

	prepare_shellcode(shellcode_text, shellcode_size);

	printf("[-] writing shellcode text...\n");

	err = write_remote_memory(target, shellcode_text_vaddr,
		shellcode_text, shellcode_size);
	if (err)
		goto out;

	printf("[-] writing shellcode stack...\n");

	/* Put the return address onto the stack */
	unsigned long retaddr_vaddr =
		shellcode_stack_vaddr + SHELLCODE_STACK_SIZE - 8;
	err = write_remote_memory(target, retaddr_vaddr,
		&shellcode_text_vaddr, sizeof(shellcode_text_vaddr));
	if (err)
		goto out;

	printf("[+] shellcode injected\n");
out:
	return err;
}
