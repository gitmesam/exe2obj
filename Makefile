MFD := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
INSTALL = install
STRIP = strip
DESTDIR ?= /usr/bin
GIT = git

OBJS = main.o options.o symbols.o utils.o section.o
CFLAGS = -g -O2

# Versioning
VERSION ?= $(shell cd ${MFD} && ${GIT} describe --always --dirty --tags --long --abbrev=8)
VERSION_MSG ?= "${VERSION}"

all: exe2obj

exe2obj: $(OBJS)
	$(CC) $^ -lelf  -o $@ -static

%.o: $(MFD)/src/%.c
	$(CC) $^ $(CPPFLAGS) $(CFLAGS) -c -o $@ -DGIT_VERSION="\"$(VERSION)\"" -DGIT_DESCRIBE="\"$(VERSION_MSG)\""

install:
	$(INSTALL) exe2obj $(DESTDIR)
	$(STRIP) $(DESTDIR)/exe2obj

clean:
	rm -f $(OBJS) exe2obj
