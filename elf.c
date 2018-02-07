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

#include "elf.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>

#include "procfs.h"

typedef struct {
	Elf64_Word nbucket;
	Elf64_Word nchain;
	/* an array of buckets followed by an array of chains */
	Elf64_Word entries[];
} Elf64_Hash;

struct dynamic_section {
	unsigned long vaddr;
	unsigned long size;

	const Elf64_Dyn *entries;
	unsigned long count;
};

struct dynstr_section {
	unsigned long vaddr;
	unsigned long size;

	const char *strings;
};

struct dynsym_section {
	unsigned long vaddr;
	unsigned long syment;

	const Elf64_Sym *symbols;
	unsigned long count;
};

struct hash_section {
	unsigned long vaddr;

	const Elf64_Hash *table;
};

struct symbol_table {
	unsigned long base_vaddr;
	struct dynstr_section dynstr;
	struct dynsym_section dynsym;
	struct hash_section hash;
};

static const void* resolve_vaddr(unsigned long vaddr, struct library *mapping)
{
	for (size_t i = 0; i < mapping->region_count; i++) {
		struct memory_region *region = &mapping->regions[i];
		if (region->vaddr_low <= vaddr && vaddr < region->vaddr_high)
			return region->content + (vaddr - region->vaddr_low);
	}
	return NULL;
}

static bool valid_elf_header(const Elf64_Ehdr *ehdr)
{
	if (!(ehdr->e_ident[EI_MAG0] == ELFMAG0 &&
	      ehdr->e_ident[EI_MAG1] == ELFMAG1 &&
	      ehdr->e_ident[EI_MAG2] == ELFMAG2 &&
	      ehdr->e_ident[EI_MAG3] == ELFMAG3))
	{
		fprintf(stderr, "[!] invalid ELF magic: '%c%c%c%c'\n",
			ehdr->e_ident[EI_MAG0], ehdr->e_ident[EI_MAG1],
			ehdr->e_ident[EI_MAG2], ehdr->e_ident[EI_MAG3]);
		return false;
	}

	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "[!] unsupported ELF class: %d\n",
			ehdr->e_ident[EI_CLASS]);
		return false;
	}

	if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
		fprintf(stderr, "[!] unsupported ELF byte order: %d\n",
			ehdr->e_ident[EI_DATA]);
		return false;
	}

	if (ehdr->e_ident[EI_VERSION] != EV_CURRENT) {
		fprintf(stderr, "[!] invalid ELF version: %d\n",
			ehdr->e_ident[EI_VERSION]);
		return false;
	}

	if (ehdr->e_ident[EI_OSABI] != ELFOSABI_LINUX) {
		fprintf(stderr, "[!] non-Linux ELF image: %d\n",
			ehdr->e_ident[EI_OSABI]);
		return false;
	}

	if (ehdr->e_type != ET_DYN) {
		fprintf(stderr, "[!] ELF is not a shared object: %d\n",
			ehdr->e_type);
		return false;
	}

	if (ehdr->e_machine != EM_X86_64) {
		fprintf(stderr, "[!] ELF image is not x86_64: %d\n",
			ehdr->e_machine);
		return false;
	}

	return true;
}

struct program_headers {
	const Elf64_Phdr *headers;
	uint16_t count;
};

static int locate_program_headers(struct library *mapping,
		struct program_headers *ph)
{
	unsigned long base_vaddr = mapping->regions[0].vaddr_low;
	const Elf64_Ehdr *ehdr = mapping->regions[0].content;

	if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) {
		fprintf(stderr, "[!] missing ELF program headers\n");
		return -1;
	}

	ph->count = ehdr->e_phnum;
	ph->headers = resolve_vaddr(base_vaddr + ehdr->e_phoff, mapping);

	if (!ph->headers) {
		fprintf(stderr, "[!] invalid program header vaddr: %lx\n",
			base_vaddr + ehdr->e_phoff);
		return -1;
	}

	return 0;
}

static const Elf64_Phdr *find_pt_dynamic_header(struct program_headers *ph)
{
	/*
	 * Actually, ELF also has a wacky special case for when there are
	 * more than PN_XNUM program headers, but we do not handle it here
	 * as this will require access to section headers.
	 */
	for (uint16_t i = 0; i < ph->count; i++) {
		if (ph->headers[i].p_type == PT_DYNAMIC) {
			return &ph->headers[i];
		}
	}
	return NULL;
}

static int locate_dynamic_section(struct library *mapping,
		struct dynamic_section *dynamic)
{
	struct program_headers ph;

	/*
	 * In order to locate the ".dynamic" section we have to use program
	 * headers, not section headers. Usually the section headers are not
	 * mapped into memory as they are not necessary for library loading.
	 */
	if (locate_program_headers(mapping, &ph) < 0)
		return -1;

	/*
	 * Scan through the headers to find the PT_DYNAMIC one. This is the
	 * program header that describes where exactly the .dynamic section
	 * is located when loaded.
	 */
	const Elf64_Phdr *pt_dynamic = find_pt_dynamic_header(&ph);
	if (!pt_dynamic) {
		fprintf(stderr, "[!] missing PT_DYNAMIC header\n");
		return -1;
	}

	/*
	 * Now we can locate the section data in our memory mapping.
	 * The 'p_vaddr' field actually contains virtual address _offset_
	 * of the ".dynamic" section, not its absolute virtual address.
	 */
	unsigned long base_vaddr = mapping->regions[0].vaddr_low;
	dynamic->vaddr = base_vaddr + pt_dynamic->p_vaddr;
	dynamic->size = pt_dynamic->p_memsz;
	dynamic->entries = resolve_vaddr(dynamic->vaddr, mapping);
	dynamic->count = dynamic->size / sizeof(Elf64_Dyn);

	if (!dynamic->entries) {
		fprintf(stderr, "[!] invalid .dynamic section vaddr: %lx\n",
			dynamic->vaddr);
		return -1;
	}

	return 0;
}

static int locate_dynstr_section(struct dynamic_section *dynamic,
		struct library *mapping, struct dynstr_section *dynstr)
{
	dynstr->vaddr = 0;
	dynstr->size = 0;

	for (unsigned long i = 0; i < dynamic->count; i++) {
		if (dynamic->entries[i].d_tag == DT_STRTAB)
			dynstr->vaddr = dynamic->entries[i].d_un.d_ptr;

		if (dynamic->entries[i].d_tag == DT_STRSZ)
			dynstr->size = dynamic->entries[i].d_un.d_val;

		if (dynamic->entries[i].d_tag == DT_NULL)
			break;
	}

	if (!dynstr->vaddr) {
		fprintf(stderr, "[!] missing DT_STRTAB entry\n");
		return -1;
	}
	if (!dynstr->size) {
		fprintf(stderr, "[!] missing DT_STRSZ entry\n");
		return -1;
	}

	dynstr->strings = resolve_vaddr(dynstr->vaddr, mapping);

	if (!dynstr->strings) {
		fprintf(stderr, "[!] invalid .dynstr section vaddr: %lx\n",
			dynstr->vaddr);
		return -1;
	}

	return 0;
}

static int locate_dynsym_section(struct dynamic_section *dynamic,
		struct library *mapping, struct dynsym_section *dynsym)
{
	dynsym->vaddr = 0;
	dynsym->syment = 0;

	for (unsigned long i = 0; i < dynamic->count; i++) {
		if (dynamic->entries[i].d_tag == DT_SYMTAB)
			dynsym->vaddr = dynamic->entries[i].d_un.d_ptr;

		if (dynamic->entries[i].d_tag == DT_SYMENT)
			dynsym->syment = dynamic->entries[i].d_un.d_val;

		if (dynamic->entries[i].d_tag == DT_NULL)
			break;
	}

	if (!dynsym->vaddr) {
		fprintf(stderr, "[!] missing DT_SYMTAB entry\n");
		return -1;
	}
	if (!dynsym->syment) {
		fprintf(stderr, "[!] missing DT_SYMENT entry\n");
		return -1;
	}

	dynsym->symbols = resolve_vaddr(dynsym->vaddr, mapping);
	dynsym->count = 0;

	if (!dynsym->symbols) {
		fprintf(stderr, "[!] invalid .dynsym section vaddr: %lx\n",
			dynsym->vaddr);
		return -1;
	}

	return 0;
}

static int locate_hash_section(struct dynamic_section *dynamic,
		struct library *mapping, struct hash_section *hash)
{
	hash->vaddr = 0;

	for (unsigned long i = 0; i < dynamic->count; i++) {
		if (dynamic->entries[i].d_tag == DT_HASH)
			hash->vaddr = dynamic->entries[i].d_un.d_ptr;

		if (dynamic->entries[i].d_tag == DT_NULL)
			break;
	}

	if (!hash->vaddr) {
		fprintf(stderr, "[!] missing DT_HASH entry\n");
		return -1;
	}

	hash->table = resolve_vaddr(hash->vaddr, mapping);

	if (!hash->table) {
		fprintf(stderr, "[!] invalid .hash section vaddr: %lx\n",
			hash->vaddr);
		return -1;
	}

	return 0;
}

struct symbol_table* find_dynamic_symbol_table(struct library *mapping)
{
	if (mapping->region_count < 1) {
		fprintf(stderr, "[*] no memory regions to look at: %zu\n",
			mapping->region_count);
		return NULL;
	}

	/*
	 * This ELF image has been successfully loaded so we can be sure that
	 * it is valid (and don't perform all the safety checks). However, we
	 * should still check whether we have a valid base address, and if it
	 * contains an ELF image that we can parse. The first mapped region
	 * should start with an ELF header from which we can go further.
	 */

	if (!valid_elf_header(mapping->regions[0].content)) {
		fprintf(stderr, "[*] sorry, this does not look like an ELF\n");
		return NULL;
	}

	printf("[.] validated ELF header\n");

	/*
	 * After we're sure the ELF is fine, we need to know where the
	 * ".dynamic" section has been loaded into memory. This section
	 * describes all symbols exported for dynamic linking.
	 */

	struct dynamic_section dynamic;

	if (locate_dynamic_section(mapping, &dynamic) < 0) {
		fprintf(stderr, "[*] .dynamic section not found\n");
		return NULL;
	}

	printf("[.] found .dynamic section at %lx (%ld bytes)\n",
		dynamic.vaddr, dynamic.size);

	/*
	 * Now we need to scan through the ".dynamic" section which
	 * contains an array of tagged structures. We are interested
	 * in the information about the dynamic string and symbol tables
	 * (stored in the ".dynstr" and ".dynsym" sections accordingly)
	 * as well as the hash table of symbol names (".hash" section).
	 */

	struct dynstr_section dynstr;
	struct dynsym_section dynsym;
	struct hash_section hash;

	if (locate_dynstr_section(&dynamic, mapping, &dynstr) < 0) {
		fprintf(stderr, "[*] .dynstr section not found\n");
		return NULL;
	}
	if (locate_dynsym_section(&dynamic, mapping, &dynsym) < 0) {
		fprintf(stderr, "[*] .dynsym section not found\n");
		return NULL;
	}
	if (locate_hash_section(&dynamic, mapping, &hash) < 0) {
		fprintf(stderr, "[*] .hash section not found\n");
		return NULL;
	}

	printf("[.] found .dynstr  section at %lx (%ld bytes)\n",
		dynstr.vaddr, dynstr.size);
	printf("[.] found .dynsym  section at %lx (%ld bytes per entry)\n",
		dynsym.vaddr, dynsym.syment);
	printf("[.] found .hash    section at %lx\n", hash.vaddr);

	/*
	 * The number of entries in the symbol table is inferred from
	 * the size of the symbol hash table. Because of ELF reasons.
	 */

	dynsym.count = hash.table->nchain;

	printf("[.] dynamic symbol count: %ld\n", dynsym.count);

	/*
	 * And now we can finally repackage and return the result.
	 */

	struct symbol_table *table = calloc(1, sizeof(*table));
	if (!table) {
		fprintf(stderr, "[*] failed to allocate symbol table\n");
		return NULL;
	}

	table->base_vaddr = mapping->regions[0].vaddr_low;
	table->dynstr = dynstr;
	table->dynsym = dynsym;
	table->hash = hash;

	return table;
}

void free_symbol_table(struct symbol_table *table)
{
	free(table);
}
