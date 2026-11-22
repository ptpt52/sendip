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
SENDIP_CPPFLAGS = "-DSENDIP_LIBS=\"$(LIBDIR)\""
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
LIBDIR_STAMP = .sendip-libdir

include mec/modules.mk
MEC_PROTOCOL_MODULES = $(addprefix mec/,$(MEC_PROTOS))
MEC_MODULES = $(MEC_PROTOCOL_MODULES) $(addprefix mec/,$(MEC_CRYPTOS))
BASE_TARGETS = $(LIBOBJS) sendip.o gnugetopt.o gnugetopt1.o $(PROTOS)
DEP_TARGETS = $(BASE_TARGETS) $(MEC_MODULES)

all:	$(LIBS) sendip $(PROTOS) $(MEC_MODULES)

man: sendip.1 sendip.spec sendipman.html

sendip: sendip.o gnugetopt.o gnugetopt1.o compact.o filearray.o
	$(CC) $(CFLAGS) $(LDFLAGS) $(SENDIP_LDFLAGS) -o $@ $^ $(SENDIP_LDLIBS) $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(SENDIP_CPPFLAGS) $(CFLAGS) $(SENDIP_CFLAGS) $(DEPFLAGS) -c -o $@ $<

# Both loaders embed LIBDIR. Keep the stamp's timestamp when it is unchanged.
$(LIBDIR_STAMP): FORCE_LIBDIR
	@tmp=$$(mktemp "$@.XXXXXXXX") || exit 1; \
	trap 'rm -f "$$tmp"' 0; \
	trap 'exit 1' HUP INT TERM; \
	printf '%s\n' "$(LIBDIR)" > "$$tmp" && \
	if ! cmp -s "$$tmp" "$@"; then mv -f "$$tmp" "$@"; fi

sendip.o: $(LIBDIR_STAMP)

libsendipaux.a: $(LIBOBJS) Makefile
	@tmpdir=$$(mktemp -d "$@.XXXXXXXX") || exit 1; \
	trap 'rm -f "$$tmpdir/$@"; rmdir "$$tmpdir"' 0; \
	trap 'exit 1' HUP INT TERM; \
	$(AR) crs "$$tmpdir/$@" $(LIBOBJS) && \
	mv -f "$$tmpdir/$@" "$@"

subdirs: $(MEC_MODULES)

protoname.o:	mec/protoname.c
	$(CC) -o $@ -c -I. $(CPPFLAGS) $(SENDIP_CPPFLAGS) $(CFLAGS) $(SENDIP_CFLAGS) $(DEPFLAGS) $<

headers.o:	mec/headers.c
	$(CC) -o $@ -c -I. $(CPPFLAGS) $(SENDIP_CPPFLAGS) $(CFLAGS) $(SENDIP_CFLAGS) $(DEPFLAGS) $<

parseargs.o:	mec/parseargs.c
	$(CC) -o $@ -c -I. $(CPPFLAGS) $(SENDIP_CPPFLAGS) $(CFLAGS) $(SENDIP_CFLAGS) $(DEPFLAGS) $<

cryptomod.o:	mec/cryptomod.c $(LIBDIR_STAMP)
	$(CC) -o $@ -c -I. $(CPPFLAGS) $(SENDIP_CPPFLAGS) $(CFLAGS) $(SENDIP_CFLAGS) $(DEPFLAGS) $<

crc32.o: mec/crc32table.h mec/crc32.c
	$(CC) -o $@ -c -I. $(CPPFLAGS) $(SENDIP_CPPFLAGS) $(CFLAGS) $(SENDIP_CFLAGS) $(DEPFLAGS) mec/crc32.c

#mec/crc32table.h: mec/gen_crc32table
#	mec/gen_crc32table > mec/crc32table.h

# This requires help2man; a customized local copy is included
sendip.1:	$(PROGS) $(PROTOS) $(MEC_PROTOCOL_MODULES) VERSION help2man.sendip mec/modules.mk
	@tmpdir=$$(mktemp -d "$@.XXXXXXXX") || exit 1; \
	trap 'rm -f "$$tmpdir/$@"; rmdir "$$tmpdir"' 0; \
	trap 'exit 1' HUP INT TERM; \
	./help2man.sendip -n "Send arbitrary IP packets" -N -- \
		$(addprefix ./,$(PROTOS) $(MEC_PROTOCOL_MODULES)) > "$$tmpdir/$@" && \
	test -s "$$tmpdir/$@" && mv -f "$$tmpdir/$@" "$@"

# This requires man2html, a relatively recent (post-2003?) one, at that
sendipman.html:	sendip.1
	@tmpdir=$$(mktemp -d "$@.XXXXXXXX") || exit 1; \
	trap 'rm -f "$$tmpdir/converted" "$$tmpdir/$@"; rmdir "$$tmpdir"' 0; \
	trap 'exit 1' HUP INT TERM; \
	man2html "$<" > "$$tmpdir/converted" && \
	sed '1d' "$$tmpdir/converted" > "$$tmpdir/$@" && \
	test -s "$$tmpdir/$@" && mv -f "$$tmpdir/$@" "$@"

sendip.spec:	sendip.spec.in VERSION
	@tmpdir=$$(mktemp -d "$@.XXXXXXXX") || exit 1; \
	trap 'rm -f "$$tmpdir/$@"; rmdir "$$tmpdir"' 0; \
	trap 'exit 1' HUP INT TERM; \
	source_version=$$(cat VERSION) || exit 1; \
	if [ -z "$$source_version" ]; then printf '%s\n' 'VERSION is empty' >&2; exit 1; fi; \
	rpm_version=$$(printf '%s' "$$source_version" | tr '-' '.') && \
	{ printf '%%define source_version %s\n' "$$source_version" && \
	  printf '%%define ver %s\n' "$$rpm_version" && \
	  cat "$<"; } > "$$tmpdir/$@" && \
	mv -f "$$tmpdir/$@" "$@"

define build_module
$(CC) $(CPPFLAGS) -I. $(SENDIP_CPPFLAGS) $(MODULE_CPPFLAGS) $(CFLAGS) $(SENDIP_CFLAGS) \
	$(DEPFLAGS) $(LIBCFLAGS) $(LDFLAGS) -o $@ $< $(LIBS) $(LDLIBS)
endef

%.so: %.c $(LIBS)
	$(build_module)

mec/hop.so: private MODULE_CPPFLAGS = -DHOP_OPT
mec/dest.so: private MODULE_CPPFLAGS = -DDEST_OPT
mec/dest.so: mec/hop.c $(LIBS)
	$(build_module)

.PHONY:	all subdirs man clean clean-mec veryclean install install-mec FORCE_LIBDIR

clean: clean-mec
			rm -f $(BASE_TARGETS) $(addsuffix .d,$(BASE_TARGETS)) $(PROGS) $(LIBS) $(LIBDIR_STAMP) core gmon.out

clean-mec:
			rm -f $(MEC_MODULES) $(addsuffix .d,$(MEC_MODULES)) mec/core mec/gmon.out

veryclean:
			$(MAKE) clean
			rm -f sendip.spec sendip.1

install:		all
			if [ ! -s sendip.1 ]; then $(MAKE) sendip.1; fi
			mkdir -p "$(DESTDIR)$(BINDIR)" "$(DESTDIR)$(MANDIR)" "$(DESTDIR)$(LIBDIR)"
			$(INSTALL) -m 755 $(PROGS) "$(DESTDIR)$(BINDIR)/"
			$(INSTALL) -m 644 sendip.1 "$(DESTDIR)$(MANDIR)/"
			$(INSTALL) -m 755 $(PROTOS) $(MEC_MODULES) "$(DESTDIR)$(LIBDIR)/"

install-mec: subdirs
			mkdir -p "$(DESTDIR)$(LIBDIR)"
			$(INSTALL) -m 755 $(MEC_MODULES) "$(DESTDIR)$(LIBDIR)/"

# Missing dependency files force a one-time rebuild of older cached outputs.
$(DEP_TARGETS): %: %.d
%.o.d: ;
%.so.d: ;

-include $(wildcard $(addsuffix .d,$(DEP_TARGETS)))
