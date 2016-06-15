#include <stdlib.h>
#include <string.h>

#include "section.h"
#include "utils.h"
#include "symbols.h"

Elf_Scn * e2o_create_section(Elf *elf, GElf_Shdr *shdr)
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

uint32_t e2o_add_name_in_section_table(Elf *elf, char *sh_name)
{
    GElf_Ehdr ehdr;
    Elf_Scn *shstrtab;
    Elf_Data *d;

    if (gelf_getehdr(elf, &ehdr) == NULL)
        display_elf_error_and_exit();
    shstrtab = elf_getscn(elf, ehdr.e_shstrndx);
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

void e2o_create_section_symbol_table(Elf *elf)
{
    GElf_Shdr shdr;
    GElf_Ehdr ehdr;

    if (gelf_getehdr(elf, &ehdr) == NULL)
        display_elf_error_and_exit();

    /* create .shstrtab*/
    memset(&shdr, 0, sizeof(shdr));
    shdr.sh_name = 1;
    shdr.sh_type = SHT_STRTAB;
    ehdr.e_shstrndx = elf_ndxscn( e2o_create_section(elf, &shdr) );

    if (gelf_update_ehdr(elf, &ehdr) == 0)
        display_elf_error_and_exit();

    /* start to add symbol */
    e2o_add_name_in_section_table(elf, "");
    e2o_add_name_in_section_table(elf, ".shstrtab");
}

void e2o_create_symbol_table(Elf *elf)
{
    GElf_Shdr shdr;

    /* create .symtab */
    memset(&shdr, 0, sizeof(shdr));
    shdr.sh_name = e2o_add_name_in_section_table(elf, ".symtab");
    shdr.sh_type = SHT_SYMTAB;
    shdr.sh_entsize = gelf_fsize(elf, ELF_T_SYM, 1, EV_CURRENT);
    shdr.sh_link = 3; /* FIXME: value of symtab */
    e2o_create_section(elf, &shdr);

    /* create .strtab */
    memset(&shdr, 0, sizeof(shdr));
    shdr.sh_name = e2o_add_name_in_section_table(elf, ".strtab");
    shdr.sh_type = SHT_STRTAB;
    e2o_create_section(elf, &shdr);

    /* start to add symbol */
    e2o_add_name_in_symbol_table(elf, "");
}
