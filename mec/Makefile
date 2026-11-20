#configureable stuff
PREFIX ?= /usr
LIBDIR ?= $(PREFIX)/lib/sendip
DESTDIR ?=
#For most systems, this works
INSTALL ?= install
#For Solaris, you may need
#INSTALL=/usr/ucb/install

CFLAGS +=	-pipe -Wall -Wpointer-arith -Wwrite-strings \
	-Wstrict-prototypes -Wnested-externs -Winline -Werror -O3 -Wcast-align
# Required flags remain present when callers supply CFLAGS/CPPFLAGS.
SENDIP_CPPFLAGS = -I.. "-DSENDIP_LIBS=\"$(LIBDIR)\""
SENDIP_CFLAGS = -fPIC -fsigned-char
#-Wcast-align causes problems on solaris, but not serious ones
LDFLAGS ?=
LDLIBS ?=
LIBCFLAGS= -shared
CC ?=	gcc
AR ?=	ar
DEPFLAGS = -MMD -MP -MF $@.d -MT $@


include modules.mk
PROTOS= $(MEC_PROTOS)
CRYPTOS= $(MEC_CRYPTOS)

LIBS= ../libsendipaux.a

all:	$(PROTOS) $(CRYPTOS)

%.so: %.c $(LIBS)
			$(CC) $(CPPFLAGS) $(SENDIP_CPPFLAGS) $(CFLAGS) $(SENDIP_CFLAGS) $(DEPFLAGS) $(LIBCFLAGS) $(LDFLAGS) -o $@ $< $(LIBS) $(LDLIBS)

hop.so: hop.c $(LIBS)
			$(CC) -DHOP_OPT $(CPPFLAGS) $(SENDIP_CPPFLAGS) $(CFLAGS) $(SENDIP_CFLAGS) $(DEPFLAGS) $(LIBCFLAGS) $(LDFLAGS) -o $@ $< $(LIBS) $(LDLIBS)

dest.so: hop.c $(LIBS)
			$(CC) -DDEST_OPT $(CPPFLAGS) $(SENDIP_CPPFLAGS) $(CFLAGS) $(SENDIP_CFLAGS) $(DEPFLAGS) $(LIBCFLAGS) $(LDFLAGS) -o $@ $< $(LIBS) $(LDLIBS)

.PHONY:	all clean veryclean install

clean:
			rm -f *.o *.o.d *.so.d *~ *.so $(PROTOS) $(CRYPTOS) $(PROGS) core gmon.out

veryclean:
			$(MAKE) clean
			rm -f sendip.spec sendip.1

install:		all
			mkdir -p "$(DESTDIR)$(LIBDIR)"
			$(INSTALL) -m 755 $(PROTOS) $(CRYPTOS) "$(DESTDIR)$(LIBDIR)/"

$(PROTOS) $(CRYPTOS): %: %.d
%.so.d: ;

-include $(wildcard *.so.d)
