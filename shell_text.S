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
.set RTLD_LAZY, 1

	.align 8
shellcode_start:
	/*
	 * void *payload; // %rax
	 *
	 * payload = dlopen(shellcode_address_payload, RTLD_LAZY);
	 */
	lea	shellcode_address_payload(%rip),%rdi
	mov	$RTLD_LAZY,%rsi
	mov	shellcode_address_dlopen(%rip),%rax
	callq	*%rax

	/*
	 * if (!payload) exit(1);
	 */
	test	%rax,%rax
	jz	.Lerror_dlopen

	/*
	 * void (*entry)(void); // %rax
	 *
	 * entry = dlsym(payload, shellcode_address_entry);
	 */
	mov	%rax,%rdi
	lea	shellcode_address_entry(%rip),%rsi
	mov	shellcode_address_dlsym(%rip),%rax
	callq	*%rax

	/*
	 * if (!entry) exit(2);
	 */
	test	%rax,%rax
	jz	.Lerror_dlsym

	/*
	 * int err; // %rax
	 * pthread_t thread; // 0(%rbp)
	 *
	 * err = pthread_create(&thread, NULL, entry, NULL);
	 */
	sub	$16,%rsp
	mov	%rsp,%rdi
	xor	%rsi,%rsi
	mov	%rax,%rdx
	xor	%rcx,%rcx
	mov	shellcode_address_pthread_create(%rip),%rax
	callq	*%rax

	/*
	 * if (err) exit(3);
	 */
	test	%rax,%rax
	jnz	.Lerror_pthread_create

	/*
	 * err = pthread_detach(thread);
	 */
	mov	(%rsp),%rdi
	add	$16,%rsp
	mov	shellcode_address_pthread_detach(%rip),%rax
	callq	*%rax

	/*
	 * if (err) exit(4);
	 */
	test	%rax,%rax
	jnz	.Lerror_pthread_detach

	/*
	 * exit(0);
	 */
	xor	%rdi,%rdi
.Lout:
	mov	$__NR_exit,%rax
	syscall

.Lerror_dlopen:
	mov	$1,%rdi
	jmp	.Lout
.Lerror_dlsym:
	mov	$2,%rdi
	jmp	.Lout
.Lerror_pthread_create:
	mov	$3,%rdi
	jmp	.Lout
.Lerror_pthread_detach:
	mov	$4,%rdi
	jmp	.Lout

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
