#configureable stuff
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man1
LIBDIR ?= $(PREFIX)/lib/sendip
#For most systems, this works
INSTALL ?= install
#For Solaris, you may need
#INSTALL=/usr/ucb/install

CFLAGS=	-I.. -fPIC -fsigned-char -pipe -Wall -Wpointer-arith -Wwrite-strings \
	-Wstrict-prototypes -Wnested-externs -Winline -Werror -O3 -Wcast-align \
	-DSENDIP_LIBS=\"$(LIBDIR)\"
#-Wcast-align causes problems on solaris, but not serious ones
LDFLAGS=	-rdynamic -lm
#LDFLAGS_SOLARIS= -lsocket -lnsl -lm
LDFLAGS_SOLARIS= -lsocket -lnsl -lm -ldl
LDFLAGS_LINUX= -rdynamic -ldl -lm
LIBCFLAGS= -shared
CC=	gcc

MYPROTOS= ah.so dest.so esp.so frag.so gre.so hop.so route.so sctp.so wesp.so
MYCRYPTOS= xorauth.so xorcrypto.so
PROTOS= $(MYPROTOS)
CRYPTOS= $(MYCRYPTOS)

LIBS= ../libsendipaux.a

all:	$(PROTOS) $(CRYPTOS)

%.so: %.c $(LIBS)
			$(CC) -o $@ $(CFLAGS) $(LIBCFLAGS) $+ $(LIBS)

hop.so: hop.c $(LIBS)
			$(CC) -DHOP_OPT -o $@ $(CFLAGS) $(LIBCFLAGS) $+ $(LIBS)

dest.so: hop.c $(LIBS)
			$(CC) -DDEST_OPT -o $@ $(CFLAGS) $(LIBCFLAGS) $+ $(LIBS)

.PHONY:	clean install

clean:
			rm -f *.o *~ *.so $(PROTOS) $(CRYPTOS) $(PROGS) core gmon.out

veryclean:
			make clean
			rm -f sendip.spec sendip.1

install:		all
			[ -d $(LIBDIR) ] || mkdir -p $(LIBDIR)
			[ -d $(BINDIR) ] || mkdir -p $(BINDIR)
			[ -d $(MANDIR) ] || mkdir -p $(MANDIR)
			$(INSTALL) -m 755 $(PROTOS) $(CRYPTOS) $(LIBDIR)
