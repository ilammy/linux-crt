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

#include <getopt.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf.h"
#include "inject-thread.h"
#include "procfs.h"
#include "ptrace.h"
#include "shell.h"
#include "syscall.h"

static const struct option long_options[] = {
	{ .name = "help",    .has_arg = 0, .val = 'h'},
	{ .name = "target",  .has_arg = 1, .val = 't'},
	{ .name = "payload", .has_arg = 1, .val = 'p'},
	{ .name = "entry",   .has_arg = 1, .val = 'e'},
};

static void usage(const char *name)
{
	printf(
	"Usage:\n"
	"    %s [option]...\n"
	"\n"
	"Options:\n"
	"    --target  <PID>                 PID of the target process\n"
	"    --payload <path/to/payload.so>  payload shared object to inject\n"
	"    --entry   <entry_point>         name of the function in the payload\n"
	"\n"
	"All options are required and must be specified.\n"
	"\n",
	name);
}

pid_t target;
pid_t shell_tid;
char payload[256];
char entry[256];

unsigned long dlopen_vaddr;
unsigned long dlsym_vaddr;

unsigned long pthread_create_vaddr;
unsigned long pthread_detach_vaddr;

unsigned long syscall_ret_vaddr;

unsigned long shellcode_text_vaddr;
unsigned long shellcode_stack_vaddr;

static int inject_thread(void);

int main(int argc, char *argv[])
{
	int opt;

	while ((opt = getopt_long(argc, argv, "h", long_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;

		case 't':
			target = atoi(optarg);
			break;

		case 'p':
			strncpy(payload, optarg, sizeof(payload) - 1);
			break;

		case 'e':
			strncpy(entry, optarg, sizeof(entry) - 1);
			break;

		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (!target || !payload[0] || !entry[0]) {
		usage(argv[0]);
		return 1;
	}

	return inject_thread() ? 2 : 0;
}

static int resolve_libdl_symbols()
{
	int err = 0;
	struct library libdl;

	printf("[-] locating and mapping libdl...\n");

	err = map_remote_library(target, "/libdl-", &libdl);
	if (err < 0)
		goto out;

	printf("[+] mapped %zu regions\n", libdl.region_count);

	printf("[-] locating dynamic symbol table of libdl...\n");

	struct symbol_table *symbols = find_dynamic_symbol_table(&libdl);
	if (!symbols) {
		err = -1;
		goto unmap;
	}

	printf("[+] found dynamic symbol table\n");

	printf("[-] resolving symbols from libdl...\n");

	dlopen_vaddr  = resolve_symbol("dlopen",  symbols);
	dlsym_vaddr   = resolve_symbol("dlsym",   symbols);

	if (!dlopen_vaddr || !dlsym_vaddr) {
		err = -1;
		goto free_symbols;
	}

	printf("[+] resolved dlopen():  %lx\n", dlopen_vaddr);
	printf("[+] resolved dlsym():   %lx\n", dlsym_vaddr);

free_symbols:
	free_symbol_table(symbols);
unmap:
	unmap_remote_library(&libdl);
out:
	return err;
}

static int resolve_libpthread_symbols()
{
	int err = 0;
	struct library libpthread;

	printf("[-] locating and mapping libpthread...\n");

	err = map_remote_library(target, "/libpthread-", &libpthread);
	if (err < 0)
		goto out;

	printf("[+] mapped %zu regions\n", libpthread.region_count);

	printf("[-] locating dynamic symbol table of libpthread...\n");

	struct symbol_table *symbols = find_dynamic_symbol_table(&libpthread);
	if (!symbols) {
		err = -1;
		goto unmap;
	}

	printf("[+] found dynamic symbol table\n");

	printf("[-] resolving symbols from libpthread...\n");

	pthread_create_vaddr = resolve_symbol("pthread_create", symbols);
	pthread_detach_vaddr = resolve_symbol("pthread_detach", symbols);

	if (!pthread_create_vaddr || !pthread_detach_vaddr) {
		err = -1;
		goto free_symbols;
	}

	printf("[+] resolved pthread_create(): %lx\n", pthread_create_vaddr);
	printf("[+] resolved pthread_detach(): %lx\n", pthread_detach_vaddr);

free_symbols:
	free_symbol_table(symbols);
unmap:
	unmap_remote_library(&libpthread);
out:
	return err;
}

static int locate_syscall_trampoline()
{
	int err = 0;
	struct library libc;

	printf("[-] locating and mapping libc...\n");

	err = map_remote_library(target, "/libc-", &libc);
	if (err < 0)
		goto out;

	printf("[+] mapped %zu regions\n", libc.region_count);

	printf("[-] locating SYSCALL instruction in libc...\n");

	syscall_ret_vaddr = find_syscall_instruction(&libc);

	if (!syscall_ret_vaddr) {
		err = -1;
		goto unmap;
	}

	printf("[+] found SYSCALL instruction at %lx\n", syscall_ret_vaddr);

unmap:
	unmap_remote_library(&libc);
out:
	return err;
}

static int prepare_shellcode()
{
	int err = 0;

	printf("[-] mapping memory pages for the shellcode...\n");

	shellcode_text_vaddr =
		remote_mmap(target, syscall_ret_vaddr, 0,
			SHELLCODE_TEXT_SIZE,
			PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	shellcode_stack_vaddr =
		remote_mmap(target, syscall_ret_vaddr, 0,
			SHELLCODE_STACK_SIZE,
			PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE | MAP_STACK |
			MAP_GROWSDOWN, -1, 0);

	if (!shellcode_text_vaddr || !shellcode_stack_vaddr)
		goto error_unmap_shellcode;

	printf("[+] mapped a page for shellcode text at %lx\n",
		shellcode_text_vaddr);
	printf("[+] mapped pages for shellcode stack at %lx\n",
		shellcode_stack_vaddr);

	err = write_shellcode();
	if (err)
		goto error_unmap_shellcode;

	printf("[-] making shellcode text read-only...\n");

	err = remote_mprotect(target, syscall_ret_vaddr,
		shellcode_text_vaddr, SHELLCODE_TEXT_SIZE,
		PROT_READ | PROT_EXEC);

	if (err)
		goto error_unmap_shellcode;

	printf("[+] shellcode ready\n");

	return 0;

error_unmap_shellcode:
	if (shellcode_text_vaddr)
		remote_munmap(target, syscall_ret_vaddr,
			shellcode_text_vaddr, SHELLCODE_TEXT_SIZE);

	if (shellcode_stack_vaddr)
		remote_munmap(target, syscall_ret_vaddr,
			shellcode_stack_vaddr, SHELLCODE_STACK_SIZE);

	return -1;
}

static int unmap_shellcode()
{
	int err = 0;

	err |= remote_munmap(target, syscall_ret_vaddr,
		shellcode_text_vaddr, SHELLCODE_TEXT_SIZE);

	err |= remote_munmap(target, syscall_ret_vaddr,
		shellcode_stack_vaddr, SHELLCODE_STACK_SIZE);

	return err;
}

static int spawn_shell_thread()
{
	printf("[-] spawning a helper thread\n");

	shell_tid = remote_clone(target, syscall_ret_vaddr,
		CLONE_FILES | CLONE_FS | CLONE_IO | CLONE_SIGHAND |
		CLONE_SYSVSEM | CLONE_THREAD | CLONE_VM,
		shellcode_stack_vaddr + SHELLCODE_STACK_SIZE - 8);

	if (!shell_tid)
		return -1;

	printf("[+] new suspended thread: %d\n", shell_tid);

	return 0;
}

static int disable_clone_tracing_in_shell_thread()
{
	int err = 0;

	printf("[-] disabling tracing of suspended thread...\n");

	err = clear_ptrace_options(shell_tid);
	if (err)
		goto out;

	printf("[+] helper thread ready\n");
out:
	return err;
}

static int detach_from_target()
{
	printf("[-] detaching from process %d...\n", target);

	return ptrace_detach(target);
}

static int detach_from_shell_thread()
{
	printf("[-] detaching from helper %d...\n", shell_tid);

	return ptrace_detach(shell_tid);
}

static int resume_target_thread()
{
	printf("[-] resuming target...\n");

	return resume_thread(target);
}

static int resume_shell_thread()
{
	printf("[-] resuming helper thread...\n");

	return resume_thread(shell_tid);
}

static int wait_for_shell_thread_exit()
{
	printf("[-] waiting for helper to exit...\n");

	int exit_code = wait_for_process_exit(shell_tid);

	if (exit_code < 0)
		return -1;

	printf("[+] shell thread exited with %d\n", exit_code);

	return 0;
}

static int stop_target_thread()
{
	printf("[-] stopping target thread...\n");

	return stop_thread(target);
}

static int inject_thread()
{
	int err;

	printf("[-] attaching to process %d...\n", target);

	err = ptrace_attach(target);
	if (err)
		goto out;

	printf("[+] attached\n");

	err = resolve_libdl_symbols();
	if (err)
		goto detach;

	err = resolve_libpthread_symbols();
	if (err)
		goto detach;

	err = locate_syscall_trampoline();
	if (err)
		goto detach;

	err = prepare_shellcode();
	if (err)
		goto detach;

	err = spawn_shell_thread();
	if (err)
		goto detach;

	err = disable_clone_tracing_in_shell_thread();
	if (err)
		goto detach;

	err = resume_target_thread();
	if (err)
		goto detach;

	err = resume_shell_thread();
	if (err)
		goto detach;

	err = wait_for_shell_thread_exit();
	if (err)
		goto detach;

	err = stop_target_thread();
	if (err)
		goto detach;

	unmap_shellcode();

	err = detach_from_target();
	if (err)
		goto detach_shell;
	
	printf("[+] we're done\n");

	return 0;

detach:
	ptrace_detach(target);
out:
	return err;

detach_shell:
	ptrace_detach(shell_tid);

	return err;
}
