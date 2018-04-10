# tools
CC := gcc
RM := rm -f

# flags
CFLAGS := -ggdb -m32
LDFLAGS := -m32
LDLIBS :=

# sources
sources := sploit1.c sploit2.c sploit3.c sploit4.c sploit5.c sploit6.c run-shellcode.c
targets := $(sources:.c=)

# gmake magic
.PHONY: default all clean

#targets
default: all
all: $(targets) shellcode.bin

clean:
	$(RM) $(targets) $(sources:.c=.o) shellcode.bin

%.o: %.S
	$(CC) -m32 -c -o $@ $<

%.bin: %.o
	objcopy -S -O binary -j .text $< $@

#dependencies
$(sources:.c=.o): shellcode.h
