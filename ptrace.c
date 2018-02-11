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

#include "ptrace.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/wait.h>

int ptrace_attach(pid_t pid)
{
	/* Stop the target process and attach to it. */
	if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
		fprintf(stderr, "[*] failed to attach to process %d: %s\n",
			pid, strerror(errno));
		goto error;
	}

	/*
	 * The process is not immediately stopped, we have to wait for it.
	 * Furthermore, we have to wait for it being stopped by a SIGSTOP,
	 * not by some other signal which may have arrived before us.
	 * Also, by that time the process may be already dead and useless.
	 */
	for (;;) {
		int status = 0;

		if (waitpid(pid, &status, 0) < 0) {
			fprintf(stderr, "[*] failed to wait for PID %d: %s\n",
				pid, strerror(errno));
			goto detach;
		}

		if (WIFSIGNALED(status) || WIFEXITED(status)) {
			fprintf(stderr, "[*] PID %d is already dead\n", pid);
			goto detach;
		}

		if (WIFSTOPPED(status))
		{
			int signal = WSTOPSIG(status);

			if (signal == SIGSTOP)
				break;

			/*
			 * If this is not the signal we wanted then reinject it
			 * back into the target process and wait again.
			 */
			if (ptrace(PTRACE_CONT, pid, 0, signal) < 0) {
				fprintf(stderr, "[*] failed to reinject signal to PID %d: %s\n",
					pid, strerror(errno));
				goto detach;
			}
		}
	}

	/*
	 * While we're here, make it easier to trace system calls. With this
	 * we will be able to distinguish between breakpoints and syscalls.
	 */
	if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD) < 0) {
		fprintf(stderr, "[*] failed to set TRACESYSGOOD on PID %d: %s\n",
			pid, strerror(errno));
		goto detach;
	}

	return 0;

detach:
	if (ptrace(PTRACE_DETACH, pid, 0, 0) < 0) {
		fprintf(stderr, "[*] failed to detach from PID %d: %s\n",
			pid, strerror(errno));
	}
error:
	return -1;
}

int ptrace_detach(pid_t pid)
{
	/* Detach from the target process. Effective immediately. */
	if (ptrace(PTRACE_DETACH, pid, 0, 0) < 0) {
		fprintf(stderr, "[*] failed to detach from PID %d: %s\n",
			pid, strerror(errno));
		return -1;
	}

	return 0;
}

int get_registers(pid_t pid, struct user_regs_struct *registers)
{
	int err = 0;
	if (ptrace(PTRACE_GETREGS, pid, registers, registers) < 0) {
		err = -errno;
		fprintf(stderr, "[!] failed to get registers of %d: %s\n",
			pid, strerror(errno));
	}
	return err;
}

int set_registers(pid_t pid, struct user_regs_struct *registers)
{
	int err = 0;
	if (ptrace(PTRACE_SETREGS, pid, registers, registers) < 0) {
		err = -errno;
		fprintf(stderr, "[!] failed to set registers of %d: %s\n",
			pid, strerror(errno));
	}
	return err;
}

static int wait_for_syscall_enter_exit_stop(pid_t pid)
{
	int err = 0;

	if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0) {
		err = -errno;
		fprintf(stderr, "[!] failed to wait for syscall by %d: %s\n",
			pid, strerror(errno));
		goto out;
	}

	for (;;) {
		int status;

		if (waitpid(pid, &status, 0) < 0) {
			err = -errno;
			fprintf(stderr, "[!] failed to wait for %d: %s\n",
				pid, strerror(errno));
			goto out;
		}

		if (WIFSIGNALED(status) || WIFEXITED(status)) {
			err = -ECHILD;
			fprintf(stderr, "[!] %d is already dead\n", pid);
			goto out;
		}

		if (WIFSTOPPED(status)) {
			int signal = WSTOPSIG(status);

			if (signal == SIGTRAP | 0x80)
				break;
		}

		/*
		 * This never happens. PTRACE_SYSCALL stops only in the
		 * following caseS:
		 * - SIGKILL of the target process
		 * - PTRACE_EVENT which we don't use
		 * - SIGTRAP on syscall completion
		 */
		err = -EINVAL;
		fprintf(stderr, "[*] unexpected result of waitpid: %d\n",
			status);
		goto out;
	}
out:
	return err;
}

int wait_for_syscall_completion(pid_t pid)
{
	int err;
	/*
	 * We need to wait twice: first for the entry into the syscall,
	 * then again for the exit from it.
	 */
	err = wait_for_syscall_enter_exit_stop(pid);
	if (err)
		goto out;

	err = wait_for_syscall_enter_exit_stop(pid);
out:
	return err;
}
