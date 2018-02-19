CC = gcc
LD = gcc
AS = as
RM = rm -f

CFLAGS += -std=c11 -D_GNU_SOURCE

target = inject-thread

objects += inject-thread.o
objects += procfs.o
objects += ptrace.o
objects += elf.o
objects += syscall.o
objects += shell.o

all: $(target)

$(target): $(objects) shell_text.o
	$(LD) -o $@ $^

$(objects): %.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

shell_text.o: shell_text.S
	$(AS) -o $@ -c $<

clean:
	$(RM) shell_text.o
	$(RM) $(objects)
	$(RM) $(target)

.PHONY: all clean
