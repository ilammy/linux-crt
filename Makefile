CC = gcc
LD = gcc
RM = rm -f

CFLAGS += -std=c11 -D_GNU_SOURCE

target = inject-thread

objects += inject-thread.o
objects += procfs.o
objects += ptrace.o
objects += elf.o
objects += syscall.o

all: $(target)

$(target): $(objects)
	$(LD) -o $@ $^

$(objects): %.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	$(RM) $(objects)
	$(RM) $(target)

.PHONY: all clean
