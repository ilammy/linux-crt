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

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <sys/syscall.h>

#include "procfs.h"
#include "ptrace.h"

unsigned long find_syscall_instruction(struct library *library)
{
	for (size_t i = 0; i < library->region_count; i++) {
		struct memory_region *region = &library->regions[i];

		if (!(region->readable && region->executable))
			continue;

		const uint8_t *region_data = region->content;
		size_t region_size = region->vaddr_high - region->vaddr_low;

		if (region_size < 3)
			continue;

		/*
		 * 0F 05 syscall
		 * C3    retq
		 */
		for (size_t offset = 0; offset < region_size - 1; offset++) {
			if (region_data[offset + 0] == 0x0F &&
			    region_data[offset + 1] == 0x05 &&
			    region_data[offset + 2] == 0xC3)
			{
				return region->vaddr_low + offset;
			}
		}
	}

	fprintf(stderr, "[*] can't find a SYSCALL instruction\n");

	return 0;
}

static int set_regs_for_syscall(struct user_regs_struct *registers,
		unsigned long syscall_insn_vaddr,
		long syscall_number, int args_count, va_list args)
{
	registers->rip = syscall_insn_vaddr;
	registers->rax = syscall_number;

	for (int i = 0; i < args_count; i++) {
		switch (i) {
		case 0:
			registers->rdi = va_arg(args, long);
			break;
		case 1:
			registers->rsi = va_arg(args, long);
			break;
		case 2:
			registers->rdx = va_arg(args, long);
			break;
		case 3:
			registers->r10 = va_arg(args, long);
			break;
		case 4:
			registers->r8 = va_arg(args, long);
			break;
		case 5:
			registers->r9 = va_arg(args, long);
			break;
		default:
			fprintf(stderr, "[*] too many syscall arguments: %d\n",
				args_count);
			return -E2BIG;
		}
	}

	return 0;
}

static long perform_syscall(pid_t pid, unsigned long syscall_insn_vaddr,
		long syscall_number, int args_count, ...)
{
	int err;
	struct user_regs_struct old_registers;
	struct user_regs_struct new_registers;

	err = get_registers(pid, &old_registers);
	if (err)
		return err;

	new_registers = old_registers;

	va_list args;
	va_start(args, args_count);
	err = set_regs_for_syscall(&new_registers, syscall_insn_vaddr,
		syscall_number, args_count, args);
	va_end(args);
	if (err)
		return err;

	err = set_registers(pid, &new_registers);
	if (err)
		return err;

	err = wait_for_syscall_completion(pid, syscall_number);
	if (err)
		return err;

	err = get_registers(pid, &new_registers);
	if (err)
		return err;

	long result = new_registers.rax;

	err = set_registers(pid, &old_registers);
	if (err)
		return err;

	return result;
}

unsigned long remote_mmap(pid_t pid, unsigned long syscall_insn_vaddr,
		unsigned long addr, size_t length, int prot, int flags,
		int fd, off_t offset)
{
	long ret = perform_syscall(pid, syscall_insn_vaddr,
		__NR_mmap, 6, (long) addr, (long) length, (long) prot,
		(long) flags, (long) fd, (long) offset);

	if (-4096 < ret && ret < 0) {
		fprintf(stderr, "[*] remote mmap() in %d failed: %s\n",
			pid, strerror(-ret));
		ret = 0;
	}

	return ret;
}

int remote_mprotect(pid_t pid, unsigned long syscall_insn_vaddr,
		unsigned long addr, size_t len, int prot)
{
	long ret = perform_syscall(pid, syscall_insn_vaddr,
		__NR_mprotect, 3, (long) addr, (long) len, (long) prot);

	if (ret < 0) {
		fprintf(stderr, "[*] remote mprotect() in %d failed: %s\n",
			pid, strerror(-ret));
		ret = -1;
	}

	return ret;
}

int remote_munmap(pid_t pid, unsigned long syscall_insn_vaddr,
		unsigned long addr, size_t len)
{
	long ret = perform_syscall(pid, syscall_insn_vaddr,
		__NR_munmap, 2, (long) addr, (long) len);

	if (ret < 0) {
		fprintf(stderr, "[*] remote munmap() in %d failed: %s\n",
			pid, strerror(-ret));
		ret = -1;
	}

	return ret;
}

pid_t remote_clone(pid_t pid, unsigned long syscall_insn_vaddr,
		unsigned long flags, unsigned long stack_vaddr)
{
	long ret = perform_syscall(pid, syscall_insn_vaddr,
		__NR_clone, 2, (long) flags, (long) stack_vaddr);

	if (ret < 0) {
		fprintf(stderr, "[*] remote clone() in %d failed: %s\n",
			pid, strerror(-ret));
		ret = 0;
	}

	return ret;
}
