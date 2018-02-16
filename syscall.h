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

#ifndef LINUX_CRT_SYSCALL_H
#define LINUX_CRT_SYSCALL_H

#include <sys/mman.h>
#include <sys/types.h>

struct library;

/**
 * find_syscall_instruction() - locate a SYSCALL instruction in the library
 * @library: the library mapping to scan
 */
unsigned long find_syscall_instruction(struct library *library);

/**
 * remote_mmap() - perform an mmap() system call in remote process
 * @pid:                PID of the target process
 * @syscall_insn_vaddr: virtual address of SYSCALL instruction
 * @addr:               mmap argument: requested virtual address
 * @length:             mmap argument: requested mapping length
 * @prot:               mmap argument: requested memory protection
 * @flags:              mmap argument: mapping flags
 * @fd:                 mmap argument: the backing file
 * @offset:             mmap argument: offset in the file
 *
 * This function preserves the register state of the process.
 *
 * Returns: corresponding virtual address on success, or zero on error.
 */
unsigned long remote_mmap(pid_t pid, unsigned long syscall_insn_vaddr,
		unsigned long addr, size_t length, int prot, int flags,
		int fd, off_t offset);

/**
 * remote_mprotect() - perform an mprotect() system call in remote process
 * @pid:                PID of the target process
 * @syscall_insn_vaddr: virtual address of SYSCALL instruction
 * @addr:               mprotect argument: address of the map to update
 * @len:                mprotect argument: length of the map to update
 * @prot:               mprotect argument: desired new protection
 *
 * This function preserves the register state of the process.
 *
 * Returns: corresponding virtual address on success, or zero on error.
 */
int remote_mprotect(pid_t pid, unsigned long syscall_insn_vaddr,
		unsigned long addr, size_t len, int prot);

/**
 * remote_munmap() - perform an munmap() system call in remote process
 * @pid:                PID of the target process
 * @syscall_insn_vaddr: virtual address of SYSCALL instruction
 * @addr:               munmap argument: address of the map to remove
 * @len:                munmap argument: length of the map to remove
 *
 * This function preserves the register state of the process.
 *
 * Returns: corresponding virtual address on success, or zero on error.
 */
int remote_munmap(pid_t pid, unsigned long syscall_insn_vaddr,
		unsigned long addr, size_t len);

#endif /* LINUX_CRT_SYSCALL_H */
