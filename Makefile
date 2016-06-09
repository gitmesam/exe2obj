MFD := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
INSTALL = install
STRIP = strip
DESTDIR ?= /usr/bin
GIT = git

OBJS = main.o options.o
CFLAGS = -g -O2

# Versioning
GIT_VERSION := $(shell cd ${MFD} && ${GIT} describe --abbrev=0)
GIT_DESCRIBE := $(shell cd ${MFD} && ${GIT} describe --always --tags --long --abbrev=12 --dirty)

all: exe2obj

exe2obj: $(OBJS)
	$(CC) $^ -lelf  -o $@ -static

%.o: $(MFD)/src/%.c
	$(CC) $^ $(CPPFLAGS) $(CFLAGS) -c -o $@ -DGIT_VERSION=\"$(GIT_VERSION)\" -DGIT_DESCRIBE=\"$(GIT_DESCRIBE)\"

install:
	$(INSTALL) exe2obj $(DESTDIR)
	$(STRIP) $(DESTDIR)/exe2obj

clean:
	rm -f $(OBJS) exe2obj
