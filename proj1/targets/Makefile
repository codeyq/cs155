# tools
CC := gcc
RM := rm -f
EXECSTACK := execstack

# flags
CFLAGS := -ggdb -m32 -g -std=c99 -D_GNU_SOURCE -fno-stack-protector -mpreferred-stack-boundary=2 -Wno-format-security
LDFLAGS := -m32
LDLIBS :=

# sources
sources := target1.c target2.c target3.c target4.c target5.c target6.c extra-credit.c tmalloc.c
targets := target1 target2 target3 target4 target5 target6 extra-credit

# gmake magic
.PHONY: default all clean

#targets
default: all
all: mkexecstack

mkexecstack: $(targets)
	$(EXECSTACK) -s $(targets)

install: mkexecstack
	install -o root -t /tmp $(targets)
	chmod 4755 /tmp/target*

%.bin: %.o
	objcopy -S -O binary -j .text $< $@

%.o: %.c
	$(CC) $< -c -o $@ $(CFLAGS)

extra-credit.o: extra-credit.c
	$(CC) $< -c -o $@ -fstack-protector-all -ggdb -m32 -g -std=c99 -D_GNU_SOURCE

%.o: %.S
	$(CC) $< -c -o $@ $(CFLAGS)

clean:
	$(RM) $(targets) $(sources:.c=.o)

#dependencies
target4: tmalloc.o
tmalloc.o target4.o: tmalloc.h
