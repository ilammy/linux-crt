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

#ifndef LINUX_CRT_SHELL_H
#define LINUX_CRT_SHELL_H

/**
 * write_shellcode() - write the shellcode into the target process memory
 *
 * This function has no arguments, everything is accessible via global
 * variables.
 *
 * Returns: zero on success, negative value on error.
 */
int write_shellcode(void);

#endif /* LINUX_CRT_SHELL_H */
