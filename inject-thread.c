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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf.h"
#include "procfs.h"
#include "ptrace.h"
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

static pid_t target;
static char payload[256];
static char entry[256];

static unsigned long dlopen_vaddr;
static unsigned long dlsym_vaddr;

static unsigned long pthread_create_vaddr;
static unsigned long pthread_detach_vaddr;

static unsigned long syscall_ret_vaddr;

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

	printf("[+] mapped %d regions\n", libdl.region_count);

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

	printf("[+] mapped %d regions\n", libpthread.region_count);

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

	printf("[+] mapped %d regions\n", libc.region_count);

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

	struct library libc;

	printf("[-] locating and mapping libc...\n");

	err = map_remote_library(target, "libc", &libc);
	if (err < 0)
		goto detach;

	printf("[+] found %d libc regions\n", libc.region_count);

	printf("[-] locating dynamic symbol table of libc...\n");

	struct symbol_table *libc_symbols = find_dynamic_symbol_table(&libc);
	if (!libc_symbols)
		goto unmap_libc;

	printf("[+] found dynamic symbol table\n");

	printf("[-] resolving necessary symbols from libc...\n");

	unsigned long dlopen =
		resolve_symbol("__libc_dlopen_mode", libc_symbols);
	unsigned long dlsym =
		resolve_symbol("__libc_dlsym", libc_symbols);
	if (!dlopen || !dlsym)
		goto free_symbols;

	printf("[+] resolved __libc_dlopen_mode(): %lx\n", dlopen);
	printf("[+] resolved __libc_dlsym(): %lx\n", dlsym);

	printf("[-] locating SYSCALL instruction in libc...\n");

	unsigned long syscall_vaddr = find_syscall_instruction(&libc);
	if (!syscall_vaddr)
		goto free_symbols;

	printf("[+] found SYSCALL instruction at %lx\n", syscall_vaddr);

	struct user_regs_struct registers;

	printf("[-] saving the registers before injection...\n");

	err = get_registers(target, &registers);
	if (err)
		goto free_symbols;

	printf("[-] mapping a memory page for the shellcode...\n");

	unsigned long shellcode_vaddr =
		remote_mmap(target, syscall_vaddr, 0, 4096,
			PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	if (!shellcode_vaddr)
		goto restore_regs;

	printf("[+] mapped a page for shellcode at %lx\n", shellcode_vaddr);

	printf("[-] removing write access to shellcode...\n");

	err = remote_mprotect(target, syscall_vaddr, shellcode_vaddr, 4096,
		PROT_READ | PROT_EXEC);
	if (err < 0)
		goto restore_regs;

	printf("[+] shellcode ready\n");

restore_regs:
	printf("[-] restoring the registers after injection...\n");

	set_registers(target, &registers);

free_symbols:
	free_symbol_table(libc_symbols);

unmap_libc:
	printf("[-] unmapping libc...\n");

	unmap_remote_library(&libc);

detach:
	printf("[-] detaching from process %d...\n", target);

	err = ptrace_detach(target);

	printf("[+] we're done\n");
out:
	return err ? 2 : 0;
}
