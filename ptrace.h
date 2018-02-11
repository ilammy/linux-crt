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
 * @pid: PID of the process to wait for
 *
 * The target process must be stopped and being debugged. You should probably
 * arrange for a system call to be performed in the nearest time (or we'll
 * wait for the first one).
 *
 * Returns: zero on success, -1 on errors.
 */
int wait_for_syscall_completion(pid_t pid);

#endif /* LINUX_CRT_PTRACE_H */
