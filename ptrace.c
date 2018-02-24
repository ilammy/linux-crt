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
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>

static int wait_for_process_stop(pid_t pid, int expected_signal)
{
	for (;;) {
		int status = 0;

		if (waitpid(pid, &status, 0) < 0) {
			fprintf(stderr, "[!] failed to wait for PID %d: %s\n",
				pid, strerror(errno));
			return -1;
		}

		if (WIFSIGNALED(status)) {
			fprintf(stderr, "[!] PID %d killed by %s\n",
				pid, strsignal(WTERMSIG(status)));
			return -1;
		}

		if (WIFEXITED(status)) {
			fprintf(stderr, "[!] PID %d exited with %d\n",
				pid, WEXITSTATUS(status));
			return -1;
		}

		if (WIFSTOPPED(status)) {
			/*
			 * Use right shift instead of WSTOPSIG() to catch
			 * PTRACE_EVENTs which come as flags higher than
			 * the lowest byte extracted by WSTOPSIG().
			 */
			int stop_signal = status >> 8;

			if (stop_signal == expected_signal)
				break;

			/*
			 * If this is not the signal we wanted then reinject
			 * it back into the target process and wait again.
			 */
			if (ptrace(PTRACE_CONT, pid, 0, stop_signal) < 0) {
				fprintf(stderr, "[!] failed to reinject %s (0x%04X) into %d: %s\n",
					strsignal(stop_signal), stop_signal,
					pid, strerror(errno));
				return -1;
			}

			continue;
		}

		fprintf(stderr, "[!] unexpected waitpid() result: 0x%04X\n",
			status);
		return -1;
	}

	return 0;
}

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
	if (wait_for_process_stop(pid, SIGSTOP) < 0)
		goto detach;

	/*
	 * While we're here, make it easier to trace system calls. With this
	 * we will be able to distinguish between breakpoints and syscalls.
	 * We will also be able to trace the newly created threads.
	 */
	unsigned long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE;
	if (ptrace(PTRACE_SETOPTIONS, pid, 0, options) < 0) {
		fprintf(stderr, "[*] failed to set options on PID %d: %s\n",
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

int resume_thread(pid_t pid)
{
	if (ptrace(PTRACE_CONT, pid, 0, 0) < 0) {
		fprintf(stderr, "[*] failed to resume PID %d: %s\n",
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

	err = ptrace(PTRACE_SYSCALL, pid, 0, 0);
	if (err) {
		fprintf(stderr, "[!] failed to wait for syscall by %d: %s\n",
			pid, strerror(errno));
		goto out;
	}

	err = wait_for_process_stop(pid, SIGTRAP | 0x80);
	if (err)
		goto out;
out:
	return err;
}

static int wait_for_clone_event(pid_t pid)
{
	int err = 0;

	err = ptrace(PTRACE_CONT, pid, 0, 0);
	if (err) {
		fprintf(stderr, "[!] failed to resume %d: %s\n",
			pid, strerror(errno));
		goto out;
	}

	err = wait_for_process_stop(pid, SIGTRAP | (PTRACE_EVENT_CLONE << 8));
	if (err)
		goto out;
out:
	return err;
}

int wait_for_syscall_completion(pid_t pid, unsigned long syscall)
{
	int err;
	/*
	 * We need to wait twice: first for the entry into the syscall,
	 * then again for the exit from it.
	 */
	err = wait_for_syscall_enter_exit_stop(pid);
	if (err)
		goto out;

	/*
	 * If we expect a clone() call then we'll need to wait for
	 * the PTRACE_EVENT_CLONE during the system call invocation.
	 */
	if (syscall == __NR_clone) {
		err = wait_for_clone_event(pid);
		if (err)
			goto out;
	}

	err = wait_for_syscall_enter_exit_stop(pid);
out:
	return err;
}

int wait_for_process_exit(pid_t pid)
{
	int status = 0;

	if (waitpid(pid, &status, 0) < 0) {
		fprintf(stderr, "[*] failed to wait for PID %d: %s\n",
			pid, strerror(errno));
		return -1;
	}

	if (!WIFEXITED(status)) {
		fprintf(stderr, "[*] unexpected wait result: 0x%04X\n",
			status);
		return -1;
	}

	return WEXITSTATUS(status);
}

int stop_thread(pid_t pid)
{
	int err = 0;

	/*
	 * First send the target thread a signal to stop.
	 */
	if (kill(pid, SIGSTOP) < 0) {
		fprintf(stderr, "[*] failed to stop PID %d: %s\n",
			pid, strerror(errno));
		return -1;
	}

	/*
	 * Then wait for it to actually stop due to that signal.
	 */
	if (wait_for_process_stop(pid, SIGSTOP) < 0)
		return -1;

	return 0;
}
