#include <stdlib.h>
#include <string.h>

#include "symbols.h"
#include "utils.h"

uint32_t e2o_add_name_in_symbol_table(Elf *elf, char *name)
{
    Elf_Scn *strtab;
    Elf_Data *d;

    strtab = elf_getscn(elf, 3/*fixme*/);
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

    symtab = elf_getscn(elf, 2/*fixme*/);
    if (symtab == NULL)
        display_elf_error_and_exit();
    d = elf_getdata(symtab, NULL);
    if (d == NULL)
        display_elf_error_and_exit();
    d->d_buf = realloc(d->d_buf, d->d_size + gelf_fsize(elf, ELF_T_SYM, 1, EV_CURRENT));
    memcpy(d->d_buf + d->d_size, &sym32, gelf_fsize(elf, ELF_T_SYM, 1, EV_CURRENT));
    d->d_size += gelf_fsize(elf, ELF_T_SYM, 1, EV_CURRENT);
}
