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

#ifndef LINUX_CRT_ELF_H
#define LINUX_CRT_ELF_H

struct library;
struct symbol_table;

/**
 * find_dynamic_symbol_table() - locate the symbol table of an ELF image
 * @library: mapping of memory regions of the shared object to scan
 *
 * Returns: a non-NULL allocated opaque symbol table on success, or NULL
 * on errors or if the ELF image does not have a dynamic symbol table.
 *
 * The returned symbol table refers to the involved memory regions, so
 * the memory regions must not be freed while the symbol table is in use.
 */
struct symbol_table* find_dynamic_symbol_table(struct library *mapping);

/**
 * free_symbol_table() - free a symbol table
 * @table: the table to be freed
 */
void free_symbol_table(struct symbol_table *table);

#endif /* LINUX_CRT_ELF_H */
