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

#include "procfs.h"
#include "ptrace.h"

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

int main(int argc, char *argv[])
{
	int opt;
	int err;
	pid_t target = 0;
	char payload[1024] = {0};
	char entry[1024] = {0};

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

	printf("[-] attaching to process %d...\n", target);

	err = ptrace_attach(target);
	if (err)
		goto out;

	printf("[+] attached\n");

	struct library libc;

	printf("[-] locating and mapping libc...\n");

	err = map_remote_library(target, "libc", &libc);
	if (err < 0)
		goto detach;

	printf("[+] found %d libc regions\n", libc.region_count);

	printf("[-] unmapping libc...\n");

	unmap_remote_library(&libc);

detach:
	printf("[-] detaching from process %d...\n", target);

	err = ptrace_detach(target);

	printf("[+] we're done\n");
out:
	return err ? 2 : 0;
}
