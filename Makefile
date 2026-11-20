#configureable stuff
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man1
LIBDIR ?= $(PREFIX)/lib/sendip
DESTDIR ?=
#For most systems, this works
INSTALL ?= install
#For Solaris, you may need
#INSTALL=/usr/ucb/install

CFLAGS +=	-pipe -Wall -Wextra -Wno-unused-parameter -Wpointer-arith -Wwrite-strings \
			-Wstrict-prototypes -Wnested-externs -Winline -Werror \
			-Wcast-align -O3
# Required flags remain present when callers supply CFLAGS/CPPFLAGS.
SENDIP_CPPFLAGS = -DSENDIP_LIBS=\"$(LIBDIR)\"
SENDIP_CFLAGS = -fPIC -fsigned-char
#-Wcast-align causes problems on solaris, but not serious ones
LDFLAGS ?=
LDLIBS ?=
UNAME_S ?= $(shell uname -s)
SENDIP_LDFLAGS = -rdynamic
SENDIP_LDLIBS = -lm
ifeq ($(UNAME_S),Linux)
SENDIP_LDFLAGS += -Wl,--no-as-needed
SENDIP_LDLIBS += -ldl
else ifeq ($(UNAME_S),SunOS)
SENDIP_LDFLAGS =
SENDIP_LDLIBS += -lsocket -lnsl -ldl
endif
LIBCFLAGS= -shared
CC ?=	gcc
AR ?=	ar
DEPFLAGS = -MMD -MP -MF $@.d -MT $@

PROGS= sendip
BASEPROTOS= ipv4.so ipv6.so
IPPROTOS= icmp.so tcp.so udp.so
UDPPROTOS= rip.so ripng.so ntp.so
TCPPROTOS= bgp.so
PROTOS= $(BASEPROTOS) $(IPPROTOS) $(UDPPROTOS) $(TCPPROTOS)
LIBS= libsendipaux.a
LIBOBJS= csum.o compact.o protoname.o headers.o parseargs.o cryptomod.o crc32.o filearray.o
SUBDIRS= mec

include mec/modules.mk

all:	$(LIBS) subdirs sendip $(PROTOS)

man: sendip.1 sendip.spec sendipman.html

sendip: sendip.o gnugetopt.o gnugetopt1.o compact.o filearray.o
	$(CC) $(CFLAGS) $(LDFLAGS) $(SENDIP_LDFLAGS) -o $@ $^ $(SENDIP_LDLIBS) $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(SENDIP_CPPFLAGS) $(CFLAGS) $(SENDIP_CFLAGS) $(DEPFLAGS) -c -o $@ $<

libsendipaux.a: $(LIBOBJS)
	$(AR) vr $@ $?

subdirs: $(LIBS)
	for subdir in $(SUBDIRS) ; do \
		$(MAKE) -C "$$subdir" LIBDIR="$(LIBDIR)" || exit $$?;\
		done

protoname.o:	mec/protoname.c
	$(CC) -o $@ -c -I. $(CPPFLAGS) $(SENDIP_CPPFLAGS) $(CFLAGS) $(SENDIP_CFLAGS) $(DEPFLAGS) $<

headers.o:	mec/headers.c
	$(CC) -o $@ -c -I. $(CPPFLAGS) $(SENDIP_CPPFLAGS) $(CFLAGS) $(SENDIP_CFLAGS) $(DEPFLAGS) $<

parseargs.o:	mec/parseargs.c
	$(CC) -o $@ -c -I. $(CPPFLAGS) $(SENDIP_CPPFLAGS) $(CFLAGS) $(SENDIP_CFLAGS) $(DEPFLAGS) $<

cryptomod.o:	mec/cryptomod.c
	$(CC) -o $@ -c -I. $(CPPFLAGS) $(SENDIP_CPPFLAGS) $(CFLAGS) $(SENDIP_CFLAGS) $(DEPFLAGS) $<

crc32.o: mec/crc32table.h mec/crc32.c
	$(CC) -o $@ -c -I. $(CPPFLAGS) $(SENDIP_CPPFLAGS) $(CFLAGS) $(SENDIP_CFLAGS) $(DEPFLAGS) mec/crc32.c

#mec/crc32table.h: mec/gen_crc32table
#	mec/gen_crc32table > mec/crc32table.h

# This requires help2man; a customized local copy is included
sendip.1:	$(PROGS) $(PROTOS) subdirs VERSION help2man.sendip mec/modules.mk
	-rm -f sendip.1
	./help2man.sendip -n "Send arbitrary IP packets" -N -- $(addprefix ./,$(PROTOS)) $(addprefix ./mec/,$(MEC_PROTOS)) >sendip.1

# This requires man2html, a relatively recent (post-2003?) one, at that
sendipman.html:	sendip.1
	-rm -f sendipman.html
	-man2html sendip.1 | tail -n +2 > sendipman.html

sendip.spec:	sendip.spec.in VERSION
			{ source_version=$$(cat VERSION) && \
			  printf '%%define source_version %s\n' "$$source_version" && \
			  printf '%%define ver %s\n' "$$(printf '%s' "$$source_version" | tr '-' '.')" && \
			  cat "$<"; } > "$@"

%.so: %.c $(LIBS)
			$(CC) $(CPPFLAGS) $(SENDIP_CPPFLAGS) $(CFLAGS) $(SENDIP_CFLAGS) $(DEPFLAGS) $(LIBCFLAGS) $(LDFLAGS) -o $@ $< $(LIBS) $(LDLIBS)

.PHONY:	all subdirs man clean veryclean install

clean:
			rm -f *.o *.o.d *.so.d *~ *.so $(PROTOS) $(PROGS) $(LIBS) core gmon.out
			for subdir in $(SUBDIRS) ; do \
				$(MAKE) -C "$$subdir" clean || exit $$?;\
				done

veryclean:
			$(MAKE) clean
			rm -f sendip.spec sendip.1

install:		all
			mkdir -p "$(DESTDIR)$(BINDIR)" "$(DESTDIR)$(MANDIR)" "$(DESTDIR)$(LIBDIR)"
			$(INSTALL) -m 755 $(PROGS) "$(DESTDIR)$(BINDIR)/"
			$(INSTALL) -m 644 sendip.1 "$(DESTDIR)$(MANDIR)/"
			$(INSTALL) -m 755 $(PROTOS) "$(DESTDIR)$(LIBDIR)/"
			for subdir in $(SUBDIRS) ; do \
				$(MAKE) -C "$$subdir" LIBDIR="$(LIBDIR)" DESTDIR="$(DESTDIR)" install || exit $$?;\
				done

# Missing dependency files force a one-time rebuild of older cached outputs.
DEP_TARGETS = $(LIBOBJS) sendip.o gnugetopt.o gnugetopt1.o $(PROTOS)
$(DEP_TARGETS): %: %.d
%.o.d: ;
%.so.d: ;

-include $(wildcard *.o.d *.so.d)
