MFD := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
INSTALL = install
STRIP = strip
DESTDIR ?= /usr/bin

OBJS = main.o
CFLAGS = -g -O2

all: exe2obj

exe2obj: $(OBJS)
	$(CC) $^ -lelf  -o $@ -static

%.o: $(MFD)/src/%.c
	$(CC) $^ $(CPPFLAGS) $(CFLAGS) -c -o $@

install:
	$(INSTALL) exe2obj $(DESTDIR)
	$(STRIP) $(DESTDIR)/exe2obj

clean:
	rm -f $(OBJS) exe2obj
