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

#ifndef LINUX_CRT_PTRACE_H
#define LINUX_CRT_PTRACE_H

#include <sys/types.h>
#include <sys/user.h>

/**
 * ptrace_detach() - attach debugger to a process
 * @pid: PID of the process to attach to
 *
 * The target process must be traceable and the current process must have
 * all the required privileges and credentials.
 *
 * Returns: zero on success, -1 on errors.
 */
int ptrace_attach(pid_t pid);

/**
 * ptrace_detach() - detach debugger from a process
 * @pid: PID of the process to detach from
 *
 * The target process must be the previously attached one.
 *
 * Returns: zero on success, -1 on errors.
 */
int ptrace_detach(pid_t pid);

/**
 * resume_thread() - resume a suspended thread
 * @pid: PID of the process to resume
 *
 * The target process must be the previously attached one and not running.
 *
 * Returns: zero on success, -1 on errors.
 */
int resume_thread(pid_t pid);

/**
 * get_registers() - read process registers
 * @pid:       PID of the process to inspect
 * @registers: registers will be placed here
 *
 * The target process must be stopped and being debugged.
 *
 * Returns: zero on success, -1 on errors.
 */
int get_registers(pid_t pid, struct user_regs_struct *registers);

/**
 * set_registers() - write process registers
 * @pid:       PID of the process to update
 * @registers: these registers will be set
 *
 * The target process must be stopped and being debugged.
 *
 * Returns: zero on success, -1 on errors.
 */
int set_registers(pid_t pid, struct user_regs_struct *registers);

/**
 * wait_for_syscall_completion() - exactly what it says on the tin
 * @pid:     PID of the process to wait for
 * @syscall: number of the expected syscall
 *
 * The target process must be stopped and being debugged. You should
 * arrange for the specified system call to be performed soon.
 *
 * Returns: zero on success, -1 on errors.
 */
int wait_for_syscall_completion(pid_t pid, unsigned long syscall);

/**
 * wait_for_process_exit() - wait for a thread to exit
 * @pid: PID of the process to wait for
 *
 * The target process must be attached and running.
 *
 * Returns: non-negative exit status on success, -1 on errors.
 */
int wait_for_process_exit(pid_t pid);

/**
 * ignore_thread_stop() - consumes a SIGSTOP signal
 * @pid: PID of the newly spawned thread
 *
 * Newly cleated and attached threads get SIGSTOP sent to them. This call
 * consumes the signal while leaving the thread in trace-stopped state.
 *
 * Returns: zero on success, -1 on errors.
 */
int ignore_thread_stop(pid_t pid);

/**
 * stop_thread() - signal a thread to stop
 * @pid: PID of the process to stop
 *
 * The target process is not required to be debugged for this to work, but
 * it probably should be debugged ;)
 *
 * Returns: zero on success, -1 on errors.
 */
int stop_thread(pid_t pid);

/**
 * clear_ptrace_options() - reset ptrace options for a traced process
 * @pid: PID of the process to reset
 *
 * This clears all ptrace options set for the thread.
 *
 * Returns: zero on success, -1 on errors.
 */
int clear_ptrace_options(pid_t pid);

#endif /* LINUX_CRT_PTRACE_H */
