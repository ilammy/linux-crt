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

.section .rodata

.global shellcode_start
.global shellcode_address_dlopen
.global shellcode_address_dlsym
.global shellcode_address_pthread_create
.global shellcode_address_pthread_detach
.global shellcode_address_payload
.global shellcode_address_entry
.global shellcode_end

.set __NR_exit, 60

	.align 8
shellcode_start:
	/*
	 * Invoke exit() and terminate the thread.
	 */
	xor	%rdi,%rdi
	mov	$__NR_exit,%rax
	syscall

	.align 8
shellcode_address_dlopen:
	.space 8
shellcode_address_dlsym:
	.space 8
shellcode_address_pthread_create:
	.space 8
shellcode_address_pthread_detach:
	.space 8
shellcode_address_payload:
	.space 256
shellcode_address_entry:
	.space 256
shellcode_end:

.end
