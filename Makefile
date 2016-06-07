OBJS = src/main.o
CFLAGS = -g -O0
CPPFLAGS = -I/tmp/libelf/usr/include

all: exe2obj

exe2obj: $(OBJS)
	$(CC) $^ -L/tmp/libelf/usr/lib/x86_64-linux-gnu -lelf  -o $@

%.o: %.c
	$(CC) $^ $(CPPFLAGS) $(CFLAGS) -c -o $@

clean:
	rm -f $(OBJS) exe2obj
