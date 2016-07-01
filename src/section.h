/* This file is part of exe2obj.
 *
 * Copyright (C) 2016 STMicroelectronics
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */
#ifndef __SECTION__
#define __SECTION__ 1

#include <gelf.h>

Elf_Scn *e2o_create_section(Elf *elf, GElf_Shdr *shdr);
uint32_t e2o_add_name_in_section_table(Elf *elf, char *sh_name);
void e2o_create_section_symbol_table(Elf *elf);
void e2o_create_symbol_table(Elf *elf);
Elf_Scn *e2o_find_section_by_name(Elf *elf, char *sh_name);
Elf_Data *e2o_find_section_data_by_name(Elf *elf, char *sh_name);

#endif