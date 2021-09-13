#configureable stuff
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man1
LIBDIR ?= $(PREFIX)/lib/sendip
#For most systems, this works
INSTALL ?= install
#For Solaris, you may need
#INSTALL=/usr/ucb/install

CFLAGS=	-fPIC -fsigned-char -pipe -Wall -Wpointer-arith -Wwrite-strings \
			-Wstrict-prototypes -Wnested-externs -Winline -Werror \
			-Wcast-align -O3 \
			-DSENDIP_LIBS=\"$(LIBDIR)\"
#-Wcast-align causes problems on solaris, but not serious ones
LDFLAGS=	-g -rdynamic -lm
#LDFLAGS_SOLARIS= -g -lsocket -lnsl -lm
LDFLAGS_SOLARIS= -g -lsocket -lnsl -lm -ldl
#LDFLAGS_LINUX= -g  -rdynamic -lm -ldl
# @@ Needed some flag fixes for Ubuntu; these are ok for Fedora, also
LDFLAGS_LINUX= -rdynamic -lm --enable-dependency-linking -Wl,--no-as-needed -ldl
LIBCFLAGS= -shared
CC=	gcc

PROGS= sendip
BASEPROTOS= ipv4.so ipv6.so
IPPROTOS= icmp.so tcp.so udp.so
UDPPROTOS= rip.so ripng.so ntp.so
TCPPROTOS= bgp.so
PROTOS= $(BASEPROTOS) $(IPPROTOS) $(UDPPROTOS) $(TCPPROTOS)
LIBS= libsendipaux.a
LIBOBJS= csum.o compact.o protoname.o headers.o parseargs.o cryptomod.o crc32.o filearray.o
SUBDIRS= mec

all:	$(LIBS) subdirs sendip $(PROTOS) sendip.1 sendip.spec sendipman.html

#there has to be a nice way to do this
sendip:	sendip.o	gnugetopt.o gnugetopt1.o compact.o filearray.o
	sh -c "if [ `uname` = Linux ] ; then \
$(CC) -o $@ $(LDFLAGS_LINUX) $(CFLAGS) $+ ; \
elif [ `uname` = SunOS ] ; then \
$(CC) -o $@ $(LDFLAGS_SOLARIS) $(CFLAGS) $+ ;\
else \
$(CC) -o $@ $(LDFLAGS) $(CFLAGS) $+ ; \
fi"

libsendipaux.a: $(LIBOBJS)
	ar vr $@ $?

subdirs:
	for subdir in $(SUBDIRS) ; do \
		cd $$subdir ;\
		make  ;\
		cd ..  ;\
		done

protoname.o:	mec/protoname.c
	$(CC) -o $@ -c -I. $(CFLAGS) $+

headers.o:	mec/headers.c
	$(CC) -o $@ -c -I. $(CFLAGS) $+

parseargs.o:	mec/parseargs.c
	$(CC) -o $@ -c -I. $(CFLAGS) $+

cryptomod.o:	mec/cryptomod.c
	$(CC) -o $@ -c -I. $(CFLAGS) $+

crc32.o: mec/crc32table.h mec/crc32.c
	$(CC) -o $@ -c -I. $(CFLAGS) mec/crc32.c

mec/crc32table.h: mec/gen_crc32table
	mec/gen_crc32table > mec/crc32table.h

# This requires help2man; a customized local copy is included
sendip.1:	$(PROGS) $(PROTOS) subdirs VERSION
	-rm -f sendip.1
	./help2man.sendip -n "Send arbitrary IP packets" -N >sendip.1

# This requires man2html, a relatively recent (post-2003?) one, at that
sendipman.html:	sendip.1
	-rm -f sendipman.html
	-man2html sendip.1 | tail -n +2 > sendipman.html

sendip.spec:	sendip.spec.in VERSION
			echo -n '%define ver ' >sendip.spec
			cat VERSION >>sendip.spec
			cat sendip.spec.in >>sendip.spec

%.so: %.c $(LIBS)
			$(CC) -o $@ $(CFLAGS) $(LIBCFLAGS) $+ $(LIBS)

.PHONY:	clean install

clean:
			rm -f *.o *~ *.so $(PROTOS) $(PROGS) $(LIBS) core gmon.out
			for subdir in $(SUBDIRS) ; do \
				cd $$subdir ;\
				make clean ;\
				cd ..  ;\
				done

veryclean:
			make clean
			rm -f sendip.spec sendip.1

install:		all
			[ -d $(LIBDIR) ] || mkdir -p $(LIBDIR)
			[ -d $(BINDIR) ] || mkdir -p $(BINDIR)
			[ -d $(MANDIR) ] || mkdir -p $(MANDIR)
			$(INSTALL) -m 755 $(PROGS) $(BINDIR)
			$(INSTALL) -m 644 sendip.1 $(MANDIR)
			$(INSTALL) -m 755 $(PROTOS) $(LIBDIR)
			for subdir in $(SUBDIRS) ; do \
				cd $$subdir ;\
				make install ;\
				cd ..  ;\
				done
