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

#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <getopt.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "options.h"

struct config config;
static struct option long_options[] = {
    {"prefix",              required_argument, NULL, 'p'},
    {"no-hide",             no_argument, NULL, 'n'},
    {"stub",                no_argument, NULL, 's'},
    {"help",                no_argument, NULL, 'h'},
    {"verbose",             no_argument, NULL, 'v'},
    {"version",             no_argument, NULL, 'V'},
    {NULL, 0, NULL, 0}
};

static void setup_default_config(struct config *config)
{
    config->prefix = NULL;
    config->is_verbose = 0;
}

static void set_prefix(char *prefix)
{
    config.prefix = strdup(prefix);
    assert(config.prefix);
    config.prefix = strcat(config.prefix, "_");
}

const char no_hide_usage[] = "\
  -n, --no-hide                     Also copy symbols with non default visibility\n";
const char stub_usage[] = "\
  -n, --stub                        Automatically generate stub code using .stub.info section information\n";
const char prefix_usage[] = "\
  -p, --prefix [PREFIX]             Prepend PREFIX_ to all exported symbols\n";
const char help_usage[] = "\
  -h, --help                        Print the help message, then exit\n";
const char version_usage[] = "\
      --version                     Output version information and exit\n";

static void print_usage(char *name)
{
    fprintf(stderr, "Usage: %s [OPTION] ... INPUT_FILE OUTPUT_FILE\n\n", name);
    fprintf(stderr, no_hide_usage);
    fprintf(stderr, stub_usage);
    fprintf(stderr, prefix_usage);
    fprintf(stderr, help_usage);
    fprintf(stderr, version_usage);
}

static void bad_usage(char *name)
{
    fprintf(stderr, "Try '%s --help' for more information.\n", name);
}

static void print_version()
{
    fprintf(stderr, "exe2obj %s (%s)\n", GIT_VERSION, GIT_DESCRIBE);
}

/* public api */
void parse_options(int argc, char **argv)
{
    int opt;

    setup_default_config(&config);
    while((opt = getopt_long(argc, argv, "+p:nhvV", long_options, NULL)) != -1) {
        switch(opt) {
            case 'p':
                set_prefix(optarg);
                break;
            case 'v':
                config.is_verbose++;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
                break;
            case 'V':
                print_version();
                exit(0);
                break;
            case 'n':
                config.no_hide = 1;
                break;
            case 's':
                config.stub = 1;
                break;
            default:
                bad_usage(argv[0]);
                exit(-1);
        }
    }

    if (argc - optind != 2) {
        bad_usage(argv[0]);
        exit(-1);
    }

    /* if no prefix is given we use a default prefix build on output name */
    if (!config.prefix && argv[optind + 1]) {
        char *bn = basename(strdup(argv[optind + 1]));
        char *last_dot = rindex(bn, '.');

        if (last_dot)
            *last_dot = '\0';
        config.prefix = strcat(bn, "_");
    }
}
