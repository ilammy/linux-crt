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

#ifndef LINUX_CRT_SHELL_TEXT_H
#define LINUX_CRT_SHELL_TEXT_H

extern const char shellcode_start[];
extern const char shellcode_address_dlopen[];
extern const char shellcode_address_dlsym[];
extern const char shellcode_address_pthread_create[];
extern const char shellcode_address_pthread_detach[];
extern const char shellcode_address_payload[];
extern const char shellcode_address_entry[];
extern const char shellcode_end[];

#endif /* LINUX_CRT_SHELL_TEXT_H */
