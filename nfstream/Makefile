CC=gcc
CFLAGS=-I. -shared -Wl,
LDFLAGS=$(CFILE) -lpcap
SHARE = -soname,observer
SO=observer.so
OBJS = observer.o
CFILE = observer.c
PIC = -fPIC
PREFIX?=/usr/local
.PHONY: all

all: $(SO)

$(SO): $(CFILE) Makefile
	$(CC) $(CFLAGS)$(SHARE) -o $@ $(PIC) $(LDFLAGS)

clean:
	/bin/rm -f $(SO)