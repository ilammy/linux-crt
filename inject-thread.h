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

#ifndef LINUX_CRT_H
#define LINUX_CRT_H

#include <sys/types.h>

extern pid_t target;
extern char payload[256];
extern char entry[256];

extern unsigned long dlopen_vaddr;
extern unsigned long dlsym_vaddr;

extern unsigned long pthread_create_vaddr;
extern unsigned long pthread_detach_vaddr;

extern unsigned long syscall_ret_vaddr;

extern unsigned long shellcode_text_vaddr;
extern unsigned long shellcode_stack_vaddr;
 
#define SHELLCODE_TEXT_SIZE  4096
#define SHELLCODE_STACK_SIZE (1024 * 1024)

#endif /* LINUX_CRT_H */
