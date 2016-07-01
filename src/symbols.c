#include <stdlib.h>
#include <string.h>

#include "symbols.h"
#include "utils.h"
#include "section.h"

static char *e2o_find_symbol_name(Elf *elf, uint32_t st_name)
{
    Elf_Scn *strtab;
    Elf_Data *d;

    d = e2o_find_section_data_by_name(elf, ".strtab");
    if (d == NULL)
        display_elf_error_and_exit();

    return st_name >= d->d_size ? NULL : d->d_buf + st_name;
}

uint32_t e2o_add_name_in_symbol_table(Elf *elf, char *name)
{
    Elf_Scn *strtab;
    Elf_Data *d;

    strtab = e2o_find_section_by_name(elf, ".strtab");
    if (strtab == NULL)
        display_error_and_exit("Unable to find .strtab section\n");
    d = elf_getdata(strtab, NULL);
    if (d == NULL)
        display_elf_error_and_exit();
    d->d_buf = realloc(d->d_buf, d->d_size + strlen(name) + 1);
    memcpy(d->d_buf + d->d_size, name, strlen(name));
    d->d_size += strlen(name) + 1;
    *(char *)(d->d_buf + d->d_size - 1) = 0;

    return d->d_size - strlen(name) -1;
}

void e2o_add_symbol(Elf *elf, GElf_Sym *sym)
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

    symtab = e2o_find_section_by_name(elf, ".symtab");
    if (symtab == NULL)
        display_error_and_exit("Unable to find .symtab section\n");
    if (symtab == NULL)
        display_elf_error_and_exit();
    d = elf_getdata(symtab, NULL);
    if (d == NULL)
        display_elf_error_and_exit();
    d->d_buf = realloc(d->d_buf, d->d_size + gelf_fsize(elf, ELF_T_SYM, 1, EV_CURRENT));
    memcpy(d->d_buf + d->d_size, &sym32, gelf_fsize(elf, ELF_T_SYM, 1, EV_CURRENT));
    d->d_size += gelf_fsize(elf, ELF_T_SYM, 1, EV_CURRENT);
}

size_t e2o_find_symbol_index_by_name(Elf *elf, char *name)
{
    Elf_Data *d;
    Elf32_Sym *sym;
    int ndx = 0;

    d = e2o_find_section_data_by_name(elf, ".symtab");
    if (d == NULL)
        display_elf_error_and_exit();

    sym = d->d_buf;
    while(sym < (Elf32_Sym *)(d->d_buf + d->d_size)) {
        char *name_strtab = e2o_find_symbol_name(elf, sym->st_name);

        if (name_strtab && strcmp(name, name_strtab) == 0)
            return ndx;
        ndx++;
        sym++;
    }

    return 0;
}
