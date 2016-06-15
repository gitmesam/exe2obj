#include <stdio.h>
#include <stdlib.h>
#include <gelf.h>
#include <string.h>
#include <assert.h>

#include "utils.h"

void display_error_and_exit(char *msg)
{
    fprintf(stderr, "%s\n", msg);

    exit(-1);
}

void display_elf_error_and_exit()
{
    int elf_error = elf_errno();

    fprintf(stderr, "%s [%d]\n", elf_errmsg(elf_error), elf_error);

    exit(-1);
}

char *append_prefix(char *pre, char *name)
{
    char *res = (char *) malloc(strlen(pre) + strlen(name) + 1);

    assert(res);
    res = strcpy(res, pre);
    res = strcat(res, name);

    return res;
}
