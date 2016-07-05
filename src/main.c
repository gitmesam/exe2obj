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

#include "utils.h"
#include "options.h"
#include "symbols.h"
#include "section.h"

#ifndef R_ARM_THM_MOVW_ABS_NC
#define R_ARM_THM_MOVW_ABS_NC   47
#endif
#ifndef R_ARM_THM_MOVT_ABS
#define R_ARM_THM_MOVT_ABS      48
#endif
#ifndef R_ARM_THM_PC22
#define R_ARM_THM_PC22          10
#endif

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

static int e2o_openfiles(struct exe2obj *e2o, char *in, char *out)
{
    e2o->fin = open(in, O_RDONLY);
    if (e2o->fin < 0) {
        fprintf(stderr, "Unable to open %s\n", in);
        return e2o->fin;
    }

    e2o->fout = open(out, O_WRONLY | O_CREAT, S_IRWXU);
    if (e2o->fout < 0) {
        fprintf(stderr, "Unable to create %s\n", out);
        return e2o->fout;
    }

    return 0;
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

static char *flags_to_name(uint64_t flags)
{
    char *res = NULL;

    if (flags & SHF_EXECINSTR)
        res = append_prefix(config.prefix, "code_asset");
    else if (flags & SHF_WRITE)
        res = append_prefix(config.prefix, "data_asset");
    else
        res = append_prefix(config.prefix, "rodata_asset");

    return res;
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

static void e2o_elf_begin(struct exe2obj *e2o)
{
    e2o->ein = elf_begin(e2o->fin, ELF_C_READ, NULL);
    if (!e2o->ein)
        display_elf_error_and_exit();

    e2o->eout = elf_begin(e2o->fout, ELF_C_WRITE, NULL);
    if (!e2o->eout)
        display_elf_error_and_exit();
}

/* We expect to have 3 segments and one and only one section in each segment */
static void e2o_gather_input_info(struct exe2obj *e2o)
{
    GElf_Ehdr * ehdr = gelf_getehdr(e2o->ein, &e2o->iinfo.ehdr);
    int i;

    if (ehdr) {
        if (ehdr->e_phnum > 3)
            display_error_and_exit("More than 3 segments in input file. Please use asset.ld link script.\n");
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
                    display_error_and_exit("More that one section in segment. You certainly try to link with code not build with -masset option.\n");
                }
            } else
                display_elf_error_and_exit();
        }

    } else
        display_elf_error_and_exit();
}

/* create and setup output file elf header. We declare output as being a
   relocatable object and not an executable. */
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

static size_t e2o_copy_section(struct exe2obj *e2o, Elf_Scn *i_scn, GElf_Shdr *is)
{
    GElf_Shdr shdr;
    Elf_Scn *o_scn;
    Elf_Data *id;
    Elf_Data *od;
    char *prefix_name;

    /* section name selected according elf flags */
    prefix_name = flags_to_name(is->sh_flags);
    /* create output section */
    memset(&shdr, 0, sizeof(shdr));
    shdr.sh_name = e2o_add_name_in_section_table(e2o->eout, prefix_name);
    shdr.sh_type = is->sh_type;
    shdr.sh_flags = is->sh_flags;
    shdr.sh_addralign = is->sh_addralign;
    o_scn = e2o_create_section(e2o->eout, &shdr);
    free(prefix_name);
    if (!o_scn)
        display_elf_error_and_exit();

    /* copy content */
    if ((id = elf_getdata(i_scn, NULL)) == 0)
        display_elf_error_and_exit();
    if ((od = elf_getdata(o_scn, NULL)) == NULL)
        display_elf_error_and_exit();
    *od = *id;

    return elf_ndxscn(o_scn);
}

static size_t eo2_create_empty_rodata_section(struct exe2obj *e2o)
{
    GElf_Shdr shdr;
    Elf_Scn *o_scn;
    char *prefix_name = flags_to_name(SHF_ALLOC);

    memset(&shdr, 0, sizeof(shdr));
    shdr.sh_name = e2o_add_name_in_section_table(e2o->eout, prefix_name);
    shdr.sh_type = SHT_PROGBITS;
    shdr.sh_flags = SHF_ALLOC;
    shdr.sh_addralign = 1;
    o_scn = e2o_create_section(e2o->eout, &shdr);
    free(prefix_name);
    if (!o_scn)
        display_elf_error_and_exit();

    return elf_ndxscn(o_scn);
}

/* copy the 3 sections we are interested in. Rename them with ${prefix}_[code|data|rodata] */
static void e2o_copy_sections(struct exe2obj *e2o)
{
    GElf_Phdr phdr;
    int i;

    for(i = 0; i < 3; i++) {
        if (e2o->iinfo.section_to_copy[i]) {
            GElf_Shdr ish;

            gelf_getshdr(e2o->iinfo.section_to_copy[i], &ish);
            e2o->oinfo.section_index[i] = e2o_copy_section(e2o, e2o->iinfo.section_to_copy[i], &ish);
        } else
            e2o->oinfo.section_index[i] = eo2_create_empty_rodata_section(e2o);
    }
}

/* Create 4 symbols :
    - empty one
    - one located at start of each of the three section.
*/
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
    e2o_add_symbol(e2o->eout, &sym);

    for(i = 0; i < 3; i++) {
        GElf_Shdr sh;
        char *prefix_name;
        Elf_Scn *s = elf_getscn(e2o->eout, e2o->oinfo.section_index[i]);

        if (!s)
            display_elf_error_and_exit();
        if (!gelf_getshdr(s, &sh))
            display_elf_error_and_exit();
        prefix_name = flags_to_name(sh.sh_flags);
        sym.st_name = e2o_add_name_in_symbol_table(e2o->eout, prefix_name);
        sym.st_value = 0;
        sym.st_size = 0;
        sym.st_info = GELF_ST_INFO(STB_GLOBAL, STT_NOTYPE);
        sym.st_other = 0;
        sym.st_shndx = e2o->oinfo.section_index[i];
        e2o_add_symbol(e2o->eout, &sym);
        free(prefix_name);
    }
}

/* copy one symbol from input file to output file. We need to adjust address,
   section index and we add a prefix to the name .*/
static void e2o_copy_symbol(struct exe2obj *e2o, GElf_Sym *sym, char *name)
{
    uint32_t index;
    GElf_Sym s;
    char *prefix_name = append_prefix(config.prefix, name);

    s.st_name = e2o_add_name_in_symbol_table(e2o->eout, prefix_name);
    s.st_value = e2o_convert_symbol_address(e2o, sym->st_shndx, sym->st_value);
    s.st_size = sym->st_size;
    s.st_info = sym->st_info;
    s.st_other = sym->st_other;
    s.st_shndx = e2o_convert_symbol_index(e2o, sym->st_shndx);

    e2o_add_symbol(e2o->eout, &s);
    free(prefix_name);
}

/* copy symbols from input to output. Only golbal symbols which have a type
   will be copied. */
static void e2o_copy_symbols(struct exe2obj *e2o)
{
    Elf_Scn *symtab_in;
    GElf_Shdr symtab_sh;
    Elf_Scn *strtab_in;
    size_t strtab_idx;
    uint64_t sym_nb;
    Elf_Data *d;
    char *name;
    int i;

    /* find strtab index */
    strtab_in = e2o_find_section_by_name(e2o->ein, ".strtab");
    if (!strtab_in)
        display_error_and_exit("unable to find .strtab in input file");
    strtab_idx = elf_ndxscn(strtab_in);

    /* find input symbol table */
    symtab_in = e2o_find_section_by_name(e2o->ein, ".symtab");
    if (!symtab_in)
        display_error_and_exit("unable to find .symtab in input file");
    if (gelf_getshdr(symtab_in, &symtab_sh) == NULL)
        display_elf_error_and_exit();
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
            if (config.no_hide || GELF_ST_VISIBILITY(sym.st_other) == STV_DEFAULT)
                e2o_copy_symbol(e2o, &sym, elf_strptr(e2o->ein, strtab_idx, sym.st_name));
    }
}

static void e2o_append_one_comment_line(Elf_Scn *scn, char *comment)
{
    Elf_Data *d;

    d = elf_getdata(scn, NULL);
    if (d == NULL)
        display_elf_error_and_exit();
    d->d_buf = realloc(d->d_buf, d->d_size + strlen(comment) + 1);
    memcpy(d->d_buf + d->d_size, comment, strlen(comment));
    d->d_size += strlen(comment) + 1;
    *(char *)(d->d_buf + d->d_size - 1) = 0;
}

static void e2o_add_comment_section(struct exe2obj *e2o, int argc, char **argv)
{
    GElf_Shdr shdr;
    Elf_Scn *scn;
    char *buf;
    char *buf_r;
    int i;
    int size = 0;

    /* first create section */
    memset(&shdr, 0, sizeof(shdr));
    shdr.sh_name = e2o_add_name_in_section_table(e2o->eout, ".comment");
    shdr.sh_type = SHT_PROGBITS;
    scn = e2o_create_section(e2o->eout, &shdr);
    /* add a first line that contains program name and version number */
    size = strlen("exe2obj") + 1 + strlen(GIT_VERSION) + 1;
    buf = malloc(size);
    assert(buf);
    sprintf(buf, "exe2obj " GIT_VERSION);
    assert(strlen(buf) + 1 == size);
    e2o_append_one_comment_line(scn, buf);
    free(buf);
    /* add a second line that contains command line arguments */
    size = 0;
    for(i = 1; i < argc; i++)
        size += strlen(argv[i]) + 1;
    buf = malloc(size);
    assert(buf);
    buf_r = buf;
    for(i = 1; i < argc; i++)
        buf_r += sprintf(buf_r, (i == argc -1) ? "%s" : "%s ", argv[i]);
    assert(strlen(buf) + 1 == size);
    e2o_append_one_comment_line(scn, buf);
    free(buf);
}

static void e2o_write_out(struct exe2obj *e2o)
{
    if (elf_update(e2o->eout, ELF_C_WRITE) < 0) {
        display_elf_error_and_exit();
    }
}

static int e2o_copy_loop_size(int stack_size)
{
    return stack_size;
}

static void e2o_copy_loop_code(Elf_Data *d, int stack_size)
{
    const uint16_t stub_code_copy_loop_base[] = {0xe9dd, 0x9a00,  /*ldrd r9, r10, [sp, #0] / need to add offset>>2 in second part/ limited offset off 508 */
                                                 0xe9cd, 0x9a00}; /*strd r9, r10, [sp, #0] / need to add offset>>2 in second part/ limited offset off 508 */
    uint16_t stub_code_copy_loop[4];
    int stack_size_at_entry = stack_size;

    while(stack_size) {
        memcpy(stub_code_copy_loop, stub_code_copy_loop_base, sizeof(stub_code_copy_loop_base));
        stub_code_copy_loop[1] |= (16 + stack_size_at_entry + stack_size - 8) >> 2;
        stub_code_copy_loop[3] |= (stack_size - 8) >> 2;
        memcpy(d->d_buf + d->d_size, stub_code_copy_loop, sizeof(stub_code_copy_loop_base));
        d->d_size += sizeof(stub_code_copy_loop_base);
        stack_size -= 8;
    }
}

static int e2o_add_stub_code_with_stack(Elf *elf, char *name, int stack_size)
{
    const uint16_t stub_code_prologue[] = {0xe92d, 0x4e00};/* stmdb   sp!, {r9, sl, fp, lr} */
    const uint16_t stub_code_sub_with_stack_size[] = {0xb080 | (stack_size >> 2)};/* sub sp, #stack_size / max stack size allowed if 508 */
    const uint16_t stub_code_load_base_and_jump[] = { 0xf240, 0x0900,/* movw    r9, #:lower16:<prefix>_data */
                                                      0xf2c0, 0x0900,/* movt    r9, #:upper16:<prefix>_data */
                                                      0xf240, 0x0a00,/* movw    r10, #:lower16:<prefix>_rodata */
                                                      0xf2c0, 0x0a00,/* movt    r10, #:upper16:<prefix>_rodata */
                                                      0xf7ff, 0xfffe};/* bl <prefix>_name */
    const uint16_t stub_code_add_with_stack_size[] = {0xb000 | (stack_size >> 2)};/* sub sp, #stack_size / max stack size allowed if 508 */
    const uint16_t stub_code_prologue_epilogue[] = {0xe8bd, 0x8e00};/* ldmia.w sp!, {r9, sl, fp, pc} */
    Elf_Scn *text_info = e2o_find_section_by_name(elf, ".text");
    Elf_Data *d = e2o_find_section_data_by_name(elf, ".text");
    GElf_Sym sym;
    int stub_size;

    assert(stack_size && (stack_size % 8) == 0);
    if (!text_info || !d)
        display_elf_error_and_exit();
    /* add code */
    stub_size = sizeof(stub_code_prologue) + sizeof(stub_code_sub_with_stack_size) +
                e2o_copy_loop_size(stack_size) + sizeof(stub_code_load_base_and_jump) +
                sizeof(stub_code_add_with_stack_size) + sizeof(stub_code_prologue_epilogue);
    d->d_buf = realloc(d->d_buf, d->d_size + stub_size);
    memcpy(d->d_buf + d->d_size, stub_code_prologue, sizeof(stub_code_prologue));
    d->d_size += sizeof(stub_code_prologue);
    memcpy(d->d_buf + d->d_size, stub_code_sub_with_stack_size, sizeof(stub_code_sub_with_stack_size));
    d->d_size += sizeof(stub_code_sub_with_stack_size);
    e2o_copy_loop_code(d, stack_size);
    memcpy(d->d_buf + d->d_size, stub_code_load_base_and_jump, sizeof(stub_code_load_base_and_jump));
    d->d_size += sizeof(stub_code_load_base_and_jump);
    memcpy(d->d_buf + d->d_size, stub_code_add_with_stack_size, sizeof(stub_code_add_with_stack_size));
    d->d_size += sizeof(stub_code_add_with_stack_size);
    memcpy(d->d_buf + d->d_size, stub_code_prologue_epilogue, sizeof(stub_code_prologue_epilogue));
    d->d_size += sizeof(stub_code_prologue_epilogue);

    /* add function symbol that point to start of stub code */
    sym.st_name = e2o_add_name_in_symbol_table(elf, name);
    sym.st_value = d->d_size - stub_size + 1/* thumb code*/;
    sym.st_size = stub_size;
    sym.st_info = GELF_ST_INFO(STB_GLOBAL, STT_FUNC);
    sym.st_other = 0;
    sym.st_shndx = elf_ndxscn(text_info);
    e2o_add_symbol(elf, &sym);

    return d->d_size - stub_size;
}

static int e2o_add_stub_code_no_stack(Elf *elf, char *name)
{
    const uint16_t stub_code[] = {0xe92d, 0x4e00,/* stmdb   sp!, {r9, sl, fp, lr} */
                                  0xf240, 0x0900,/* movw    r9, #:lower16:<prefix>_data */
                                  0xf2c0, 0x0900,/* movt    r9, #:upper16:<prefix>_data */
                                  0xf240, 0x0a00,/* movw    r10, #:lower16:<prefix>_rodata */
                                  0xf2c0, 0x0a00,/* movt    r10, #:upper16:<prefix>_rodata */
                                  0xf7ff, 0xfffe,/* bl <prefix>_name */
                                  0xe8bd, 0x8e00,/* ldmia.w sp!, {r9, sl, fp, pc} */
                              };
    Elf_Scn *text_info = e2o_find_section_by_name(elf, ".text");
    Elf_Data *d = e2o_find_section_data_by_name(elf, ".text");
    GElf_Sym sym;

    if (!text_info || !d)
        display_elf_error_and_exit();
    /* add code */
    d->d_buf = realloc(d->d_buf, d->d_size + sizeof(stub_code));
    memcpy(d->d_buf + d->d_size, stub_code, sizeof(stub_code));
    d->d_size += sizeof(stub_code);

    /* add function symbol that point to start of stub code */
    sym.st_name = e2o_add_name_in_symbol_table(elf, name);
    sym.st_value = d->d_size - sizeof(stub_code) + 1/* thumb code*/;
    sym.st_size = sizeof(stub_code);
    sym.st_info = GELF_ST_INFO(STB_GLOBAL, STT_FUNC);
    sym.st_other = 0;
    sym.st_shndx = elf_ndxscn(text_info);
    e2o_add_symbol(elf, &sym);

    return d->d_size - sizeof(stub_code);
}

static void e2o_append_reloc(Elf_Data *d, int code_offset, int index, int type)
{
    /* FIXME: should be independant of 32-64 bit */
    Elf32_Rel rel;

    d->d_buf = realloc(d->d_buf, d->d_size + sizeof(rel));
    rel.r_offset = code_offset;
    rel.r_info = (index << 8) + type;
    memcpy(d->d_buf + d->d_size, &rel, sizeof(rel));
    d->d_size += sizeof(rel);
}

static void e2o_add_reloc(Elf *elf, char *name, int code_offset)
{
    Elf_Data *d = e2o_find_section_data_by_name(elf, ".rel.text");
    char *data_prefix_name = flags_to_name(SHF_ALLOC | SHF_WRITE);
    char *rodata_prefix_name = flags_to_name(SHF_ALLOC);
    char *prefix_name = append_prefix(config.prefix, name);
    int data_prefix_index;
    int rodata_prefix_index;
    int prefix_name_index;

    /* retriewe needed indexes need for relocs */
    assert(d && data_prefix_name && rodata_prefix_name && prefix_name);
    data_prefix_index = e2o_find_symbol_index_by_name(elf, data_prefix_name);
    rodata_prefix_index = e2o_find_symbol_index_by_name(elf, rodata_prefix_name);
    prefix_name_index = e2o_find_symbol_index_by_name(elf, prefix_name);
    free(data_prefix_name);
    free(rodata_prefix_name);
    free(prefix_name);
    assert(data_prefix_index && rodata_prefix_index && prefix_name_index);

    /* generate relocs */
    e2o_append_reloc(d, code_offset + 4, data_prefix_index, R_ARM_THM_MOVW_ABS_NC);
    e2o_append_reloc(d, code_offset + 8, data_prefix_index, R_ARM_THM_MOVT_ABS);
    e2o_append_reloc(d, code_offset + 12, rodata_prefix_index, R_ARM_THM_MOVW_ABS_NC);
    e2o_append_reloc(d, code_offset + 16, rodata_prefix_index, R_ARM_THM_MOVT_ABS);
    e2o_append_reloc(d, code_offset + 20, prefix_name_index, R_ARM_THM_PC22);
}

static unsigned char *e2o_insert_stub(Elf *elf, unsigned char *buf)
{
    Elf_Scn *text_info;
    int args_stack_size = *buf++;
    int offset;

    if (args_stack_size) {
        int stack_size = ((args_stack_size + 4) / 8) * 8;

        offset = e2o_add_stub_code_with_stack(elf, buf, stack_size);
        e2o_add_reloc(elf, buf, offset + 2 + e2o_copy_loop_size(stack_size));
    } else {
        offset = e2o_add_stub_code_no_stack(elf, buf);
        e2o_add_reloc(elf, buf, offset);
    }

    return buf + strlen(buf) + 1;
}

static void e2o_add_stub_code(struct exe2obj *e2o)
{
    GElf_Shdr shdr;
    Elf_Scn *scn;
    Elf_Data *stub_info_data;
    int pos = 0;
    unsigned char *buf;

    /* get .stub.info section data */
    stub_info_data = e2o_find_section_data_by_name(e2o->ein, ".stub.info");
    if (stub_info_data == NULL) {
        fprintf(stderr, ".stub.info section empty or doesn't exist. Stub code will not be generated\n");
        return ;
    }

    /* create sections */
    memset(&shdr, 0, sizeof(shdr));
    shdr.sh_name = e2o_add_name_in_section_table(e2o->eout, ".text");
    shdr.sh_type = SHT_PROGBITS;
    shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    scn = e2o_create_section(e2o->eout, &shdr);
    memset(&shdr, 0, sizeof(shdr));
    shdr.sh_name = e2o_add_name_in_section_table(e2o->eout, ".rel.text");
    shdr.sh_type = SHT_REL;
    shdr.sh_link = elf_ndxscn( e2o_find_section_by_name(e2o->eout, ".symtab") );
    shdr.sh_info = elf_ndxscn(scn);
    e2o_create_section(e2o->eout, &shdr);

    /* parsing stub_info_data and generate symbol code and reloc */
    buf = stub_info_data->d_buf;
    while (buf < (unsigned char *)stub_info_data->d_buf + stub_info_data->d_size)
        buf = e2o_insert_stub(e2o->eout, buf);
}

static int main_options_parsed(int argc, char **argv, int argc_orig, char **argv_orig)
{
    assert(elf_version(EV_CURRENT) != EV_NONE);
    if (e2o_openfiles(&exe2obj, argv[0], argv[1]))
        exit(-1);
    e2o_elf_begin(&exe2obj);
    e2o_gather_input_info(&exe2obj);
    e2o_copy_elf_header(&exe2obj);
    e2o_create_section_symbol_table(exe2obj.eout);
    e2o_create_symbol_table(exe2obj.eout);
    e2o_copy_sections(&exe2obj);
    e2o_add_symbols(&exe2obj);
    e2o_copy_symbols(&exe2obj);
    e2o_add_comment_section(&exe2obj, argc_orig, argv_orig);
    if (config.stub)
        e2o_add_stub_code(&exe2obj);

    e2o_write_out(&exe2obj);

    return 0;
}

int main(int argc, char **argv)
{
    /* parse options */
    parse_options(argc, argv);

    return main_options_parsed(argc - optind, argv + optind, argc, argv);
}
