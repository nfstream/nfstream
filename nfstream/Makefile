CFLAGS=-I. -shared -Wl,
LDFLAGS=$(CFILE) -lpcap
ifeq ($(UNAME), Darwin)
	SONAME_OPTION	=	-install_name
else
	SONAME_OPTION    =   -soname
endif

SHARE = ${SONAME_OPTION},observer
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