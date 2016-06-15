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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <gelf.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <string.h>
#include <libgen.h>

#include "options.h"

struct exe2obj_input_info {
    GElf_Ehdr ehdr;
    Elf_Scn *section_to_copy[3];
    size_t section_index[3];
    GElf_Addr section_addr[3];
};

struct exe2obj_output_info {
    size_t section_index[3];
};

struct exe2obj {
    int fin;
    int fout;
    Elf *ein;
    Elf *eout;
    struct exe2obj_input_info iinfo;
    struct exe2obj_output_info oinfo;
};

struct exe2obj exe2obj;

static void display_error_and_exit(char *msg)
{
    fprintf(stderr, "%s\n", msg);

    exit(-1);
}

static void display_elf_error_and_exit()
{
    int elf_error = elf_errno();

    fprintf(stderr, "%s [%d]\n", elf_errmsg(elf_error), elf_error);

    exit(-1);
}

static char *append_prefix(char *pre, char *name)
{
    char *res = (char *) malloc(strlen(pre) + strlen(name) + 1);

    assert(res);
    res = strcpy(res, pre);
    res = strcat(res, name);

    return res;
}

static int e2o_openfiles(struct exe2obj *e2o, char *in, char *out)
{
    e2o->fin = open(in, O_RDONLY);
    if (e2o->fin < 0)
        return e2o->fin;

    e2o->fout = open(out, O_WRONLY | O_CREAT, S_IRWXU);
    if (e2o->fout < 0)
        return e2o->fout;

    return 0;
}

static uint32_t e2o_add_name_in_section_table(struct exe2obj *e2o, char *sh_name)
{
    GElf_Ehdr ehdr;
    Elf_Scn *shstrtab;
    Elf_Data *d;

    if (gelf_getehdr(e2o->eout, &ehdr) == NULL)
        display_elf_error_and_exit();
    shstrtab = elf_getscn(e2o->eout, ehdr.e_shstrndx);
    if (shstrtab == NULL)
        display_elf_error_and_exit();
    d = elf_getdata(shstrtab, NULL);
    if (d == NULL)
        display_elf_error_and_exit();
    d->d_buf = realloc(d->d_buf, d->d_size + strlen(sh_name) + 1);
    memcpy(d->d_buf + d->d_size, sh_name, strlen(sh_name));
    d->d_size += strlen(sh_name) + 1;
    *(char *)(d->d_buf + d->d_size - 1) = 0;

    return d->d_size - strlen(sh_name) -1;
}

static uint32_t e2o_add_name_in_symbol_table(struct exe2obj *e2o, char *name)
{
    Elf_Scn *strtab;
    Elf_Data *d;

    strtab = elf_getscn(e2o->eout, 3/*fixme*/);
    if (strtab == NULL)
        display_elf_error_and_exit();
    d = elf_getdata(strtab, NULL);
    if (d == NULL)
        display_elf_error_and_exit();
    d->d_buf = realloc(d->d_buf, d->d_size + strlen(name) + 1);
    memcpy(d->d_buf + d->d_size, name, strlen(name));
    d->d_size += strlen(name) + 1;
    *(char *)(d->d_buf + d->d_size - 1) = 0;

    return d->d_size - strlen(name) -1;
}

static void e2o_add_symbol(struct exe2obj *e2o, GElf_Sym *sym)
{
    Elf_Scn *symtab;
    Elf_Data *d;
    Elf32_Sym sym32;

    sym32.st_name = sym->st_name;
    sym32.st_value = sym->st_value;
    sym32.st_size = sym->st_size;
    sym32.st_info = sym->st_info;
    sym32.st_other = sym->st_other;
    sym32.st_shndx = sym->st_shndx;

    symtab = elf_getscn(e2o->eout, 2/*fixme*/);
    if (symtab == NULL)
        display_elf_error_and_exit();
    d = elf_getdata(symtab, NULL);
    if (d == NULL)
        display_elf_error_and_exit();
    d->d_buf = realloc(d->d_buf, d->d_size + gelf_fsize(e2o->eout, ELF_T_SYM, 1, EV_CURRENT));
    memcpy(d->d_buf + d->d_size, &sym32, gelf_fsize(e2o->eout, ELF_T_SYM, 1, EV_CURRENT));
    d->d_size += gelf_fsize(e2o->eout, ELF_T_SYM, 1, EV_CURRENT);
}

static uint16_t e2o_convert_symbol_index(struct exe2obj *e2o, uint16_t shndx_in)
{
    int i;

    for(i = 0; i < 3; i++)
        if (e2o->iinfo.section_index[i] == shndx_in)
            return e2o->oinfo.section_index[i];

    fprintf(stderr, "Unable to find %d\n", shndx_in);
    return shndx_in;
}

static GElf_Addr e2o_convert_symbol_address(struct exe2obj *e2o, uint16_t shndx_in, GElf_Addr addr_in)
{
    int i;

    for(i = 0; i < 3; i++)
        if (e2o->iinfo.section_index[i] == shndx_in)
            return addr_in ? addr_in - e2o->iinfo.section_addr[i] : addr_in;

    fprintf(stderr, "Unable to find %d\n", shndx_in);
    return addr_in;
}

static void e2o_copy_symbol(struct exe2obj *e2o, GElf_Sym *sym, char *name)
{
    uint32_t index;
    GElf_Sym s;
    char *prefix_name = append_prefix(config.prefix, name);

    s.st_name = e2o_add_name_in_symbol_table(e2o, prefix_name);
    s.st_value = e2o_convert_symbol_address(e2o, sym->st_shndx, sym->st_value);
    s.st_size = sym->st_size;
    s.st_info = sym->st_info;
    s.st_other = sym->st_other;
    s.st_shndx = e2o_convert_symbol_index(e2o, sym->st_shndx);

    e2o_add_symbol(e2o, &s);
    free(prefix_name);
}

static void e2o_elf_begin(struct exe2obj *e2o)
{
    e2o->ein = elf_begin(e2o->fin, ELF_C_READ, NULL);
    if (!e2o->ein)
        display_elf_error_and_exit();

    e2o->eout = elf_begin(e2o->fout, ELF_C_WRITE, NULL);
    if (!e2o->eout)
        display_elf_error_and_exit();
}

static int is_section_belong_to_segment(GElf_Phdr *ph, GElf_Shdr *sh)
{
    if (ph->p_type == PT_LOAD) {
        if (sh->sh_addr) {
            GElf_Addr h_start = ph->p_vaddr;
            GElf_Addr h_end = h_start + ph->p_memsz;
            GElf_Addr s_start = sh->sh_addr;
            GElf_Addr s_end = s_start + sh->sh_size;

            if (s_start >= h_start && s_end <= h_end)
                return 1;
        }
    }

    return 0;
}

static void e2o_gather_input_info(struct exe2obj *e2o)
{
    GElf_Ehdr * ehdr = gelf_getehdr(e2o->ein, &e2o->iinfo.ehdr);
    int i;

    if (ehdr) {
        if (ehdr->e_phnum > 3)
            display_error_and_exit("More than 3 segments in input file\n");
        for(i = 0; i < ehdr->e_phnum; i++) {
            GElf_Phdr phdr;

            if (gelf_getphdr(e2o->ein, i, &phdr)) {
                int section_counter = 0;
                GElf_Shdr ish;
                Elf_Scn *is = NULL;

                while ((is = elf_nextscn(e2o->ein, is)) != NULL) {
                    if (gelf_getshdr(is, &ish)) {
                        if (is_section_belong_to_segment(&phdr, &ish)) {
                            section_counter++;
                            e2o->iinfo.section_to_copy[i] = is;
                            e2o->iinfo.section_index[i] = elf_ndxscn(is);
                            e2o->iinfo.section_addr[i] = ish.sh_addr;
                        }
                    } else
                        display_elf_error_and_exit();
                if (section_counter > 1)
                    display_error_and_exit("More that one section in segment\n");
                }
            } else
                display_elf_error_and_exit();
        }

    } else
        display_elf_error_and_exit();
}

static Elf_Scn * e2o_create_section(Elf *elf, GElf_Shdr *shdr)
{
    Elf_Data *d;
    Elf_Scn *res = elf_newscn(elf);

    /* fail to create section */
    if (!res)
        display_elf_error_and_exit();

    if (gelf_update_shdr(res, shdr) == 0)
        display_elf_error_and_exit();

    /* create empty data content */
    if ((d = elf_newdata(res)) == NULL)
        display_elf_error_and_exit();
    d->d_off = 0;

    return res;
}

static size_t e2o_copy_section(struct exe2obj *e2o, Elf_Scn *i_scn, GElf_Shdr *is)
{
    GElf_Shdr shdr;
    Elf_Scn *o_scn;
    Elf_Data *id;
    Elf_Data *od;
    char *prefix_name;

    /* section name selected according elf flags */
    if (is->sh_flags & SHF_EXECINSTR)
        prefix_name = append_prefix(config.prefix, "code");
    else if (is->sh_flags & SHF_WRITE)
        prefix_name = append_prefix(config.prefix, "data");
    else
        prefix_name = append_prefix(config.prefix, "rodata");
    /* create output section */
    memset(&shdr, 0, sizeof(shdr));
    shdr.sh_name = e2o_add_name_in_section_table(e2o, prefix_name);
    shdr.sh_type = is->sh_type;
    shdr.sh_flags = is->sh_flags;
    shdr.sh_addralign = is->sh_addralign;
    o_scn = e2o_create_section(e2o->eout, &shdr);
    free(prefix_name);
    if (!o_scn)
        display_elf_error_and_exit();

    /* copy data */
    if ((id = elf_getdata(i_scn, NULL)) == 0)
        display_elf_error_and_exit();
    if ((od = elf_getdata(o_scn, NULL)) == NULL)
        display_elf_error_and_exit();
    *od = *id;

    return elf_ndxscn(o_scn);
}

static void e2o_copy_sections(struct exe2obj *e2o)
{
    GElf_Phdr phdr;
    int i;

    for(i = 0; i < 3; i++) {
        if (e2o->iinfo.section_to_copy[i]) {
            GElf_Shdr ish;

            gelf_getshdr(e2o->iinfo.section_to_copy[i], &ish);
            e2o->oinfo.section_index[i] = e2o_copy_section(e2o, e2o->iinfo.section_to_copy[i], &ish);
        }
    }
}

static void e2o_copy_elf_header(struct exe2obj *e2o)
{
    GElf_Ehdr ehdr;

    if (gelf_newehdr(e2o->eout, ELFCLASS32) == 0)
        display_elf_error_and_exit();
    if (gelf_getehdr(e2o->eout, &ehdr) == NULL)
        display_elf_error_and_exit();
    ehdr.e_ident[EI_DATA] = e2o->iinfo.ehdr.e_ident[EI_DATA];
    ehdr.e_machine = e2o->iinfo.ehdr.e_machine;
    ehdr.e_type = ET_REL;
    ehdr.e_flags = e2o->iinfo.ehdr.e_flags;
    ehdr.e_version = EV_CURRENT;
    if (gelf_update_ehdr(e2o->eout, &ehdr) == 0)
        display_elf_error_and_exit();
}

static void e2o_create_section_symbol_table(struct exe2obj *e2o)
{
    GElf_Shdr shdr;
    GElf_Ehdr ehdr;

    if (gelf_getehdr(e2o->eout, &ehdr) == NULL)
        display_elf_error_and_exit();

    /* create .shstrtab*/
    memset(&shdr, 0, sizeof(shdr));
    shdr.sh_name = 1;
    shdr.sh_type = SHT_STRTAB;
    ehdr.e_shstrndx = elf_ndxscn( e2o_create_section(e2o->eout, &shdr) );

    if (gelf_update_ehdr(e2o->eout, &ehdr) == 0)
        display_elf_error_and_exit();

    /* start to add symbol */
    e2o_add_name_in_section_table(e2o, "");
    e2o_add_name_in_section_table(e2o, ".shstrtab");
}

static void e2o_create_symbol_table(struct exe2obj *e2o)
{
    GElf_Shdr shdr;

    /* create .symtab */
    memset(&shdr, 0, sizeof(shdr));
    shdr.sh_name = e2o_add_name_in_section_table(e2o, ".symtab");
    shdr.sh_type = SHT_SYMTAB;
    shdr.sh_entsize = gelf_fsize(e2o->eout, ELF_T_SYM, 1, EV_CURRENT);
    shdr.sh_link = 3; /* FIXME: value of symtab */
    e2o_create_section(e2o->eout, &shdr);

    /* create .strtab */
    memset(&shdr, 0, sizeof(shdr));
    shdr.sh_name = e2o_add_name_in_section_table(e2o, ".strtab");
    shdr.sh_type = SHT_STRTAB;
    e2o_create_section(e2o->eout, &shdr);

    /* start to add symbol */
    e2o_add_name_in_symbol_table(e2o, "");
}

static void e2o_add_symbols(struct exe2obj *e2o)
{
    int i;
    GElf_Sym sym;

    sym.st_name = 0;
    sym.st_value = 0;
    sym.st_size = 0;
    sym.st_info = 0;
    sym.st_other = 0;
    sym.st_shndx = 0;
    e2o_add_symbol(e2o, &sym);

    for(i = 0; i < 3; i++) {
        GElf_Shdr sh;
        char *prefix_name;
        Elf_Scn *s = elf_getscn(e2o->eout, e2o->oinfo.section_index[i]);

        if (!s)
            display_elf_error_and_exit();
        if (!gelf_getshdr(s, &sh))
            display_elf_error_and_exit();
        if (sh.sh_flags & SHF_EXECINSTR)
            prefix_name = append_prefix(config.prefix, "code");
        else if (sh.sh_flags & SHF_WRITE)
            prefix_name = append_prefix(config.prefix, "data");
        else
            prefix_name = append_prefix(config.prefix, "rodata");

        sym.st_name = e2o_add_name_in_symbol_table(e2o, prefix_name);
        sym.st_value = 0;
        sym.st_size = 0;
        sym.st_info = GELF_ST_INFO(STB_GLOBAL, STT_NOTYPE);
        sym.st_other = 0;
        sym.st_shndx = e2o->oinfo.section_index[i];
        e2o_add_symbol(e2o, &sym);
        free(prefix_name);
    }
}

static void e2o_copy_symbols(struct exe2obj *e2o)
{
    Elf_Scn *symtab_in;
    GElf_Shdr symtab_sh;
    Elf_Scn *strtab_in;
    GElf_Shdr strtab_sh;
    size_t strtab_idx;
    uint64_t sym_nb;
    Elf_Data *d;
    char *name;
    int i;

    /* find strtab index */
    strtab_in = NULL;
    while ((strtab_in = elf_nextscn(e2o->ein, strtab_in)) != NULL) {
        if (gelf_getshdr(strtab_in, &strtab_sh) == NULL)
            display_elf_error_and_exit();
        /* find by name */
        name = elf_strptr(e2o->ein, e2o->iinfo.ehdr.e_shstrndx, strtab_sh.sh_name);
        if (name && strcmp(name, ".strtab") == 0)
            break;
    }
    if (!strtab_in)
        display_error_and_exit("uname to find .strtab in input file");
    strtab_idx = elf_ndxscn(strtab_in);

    /* find input symbol table */
    symtab_in = NULL;
    while ((symtab_in = elf_nextscn(e2o->ein, symtab_in)) != NULL) {
        if (gelf_getshdr(symtab_in, &symtab_sh) == NULL)
            display_elf_error_and_exit();
        /* find by name */
        name = elf_strptr(e2o->ein, e2o->iinfo.ehdr.e_shstrndx, symtab_sh.sh_name);
        if (name && strcmp(name, ".symtab") == 0)
            break;
    }
    if (!symtab_in)
        display_error_and_exit("uname to find .symtab in input file");
    sym_nb = symtab_sh.sh_size / symtab_sh.sh_entsize;
    d = elf_getdata(symtab_in, NULL);
    if (d == NULL)
        display_elf_error_and_exit();

    /* loop over symbol */
    for(i = 0; i < sym_nb; i++) {
        GElf_Sym sym;

        if (gelf_getsym(d, i, &sym) == NULL)
            display_elf_error_and_exit();

        if (GELF_ST_BIND(sym.st_info) == STB_GLOBAL && GELF_ST_TYPE(sym.st_info) != STT_NOTYPE)
            e2o_copy_symbol(e2o, &sym, elf_strptr(e2o->ein, strtab_idx, sym.st_name));
    }
}

static void e2o_write_out(struct exe2obj *e2o)
{
    if (elf_update(e2o->eout, ELF_C_WRITE) < 0) {
        display_elf_error_and_exit();
    }
}

static int main_options_parsed(int argc, char **argv)
{
    assert(elf_version(EV_CURRENT) != EV_NONE);
    assert(e2o_openfiles(&exe2obj, argv[0], argv[1]) == 0);
    e2o_elf_begin(&exe2obj);
    e2o_gather_input_info(&exe2obj);
    e2o_copy_elf_header(&exe2obj);
    e2o_create_section_symbol_table(&exe2obj);
    e2o_create_symbol_table(&exe2obj);
    e2o_copy_sections(&exe2obj);
    e2o_add_symbols(&exe2obj);
    e2o_copy_symbols(&exe2obj);

    e2o_write_out(&exe2obj);

    return 0;
}

int main(int argc, char **argv)
{
    /* parse options */
    parse_options(argc, argv);

    return main_options_parsed(argc - optind, argv + optind);
}
