#AUTOMAKE_OPTIONS = foreign subdir-objects
AUTOMAKE_OPTIONS = foreign

# what flags you want to pass to the C compiler & linker
#CFLAGS = --pedantic -Wall -std=c99 -O2
#CC = gcc
AM_CFLAGS  = -std=c99 -O2 -g -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700

AM_LFLAGS  = -lsqlite3 \
             -lmysqlclient \
             -lrt \
             -lcrypto \
             -lssl \
             -lpthread

AM_LDFLAGS = -L/usr/local/mysql-8.0.3-rc/lib \
             -L/usr/local/openssl-1.1.0e/lib

AM_CPPFLAGS = -I../inc \
              -I/usr/local/mysql-8.0.3-rc/include \
              -I/usr/local/openssl-1.1.0e/include

Trenchdir = $(includedir)/Trench

# this lists the binaries to produce, the (non-PHONY, binary) targets in
# the previous manual Makefile
bin_PROGRAMS = Trench 

UIDAI_SRC = uidai/util.c \
            uidai/uidai.c \
            uidai/otp.c \
            uidai/auth.c

UIDAI_INC = uidai/common.h \
            uidai/uidai.h \
            uidai/otp.h \
            uidai/auth.h \
            uidai/util.h

UAM_SRC = uam/http.c

UAM_INC = uam/http.h

OAUTH20_SRC = oauth20/sslc.c \
              oauth20/oauth20.c

OAUTH20_INC = oauth20/sslc.h \
              oauth20/oauth20.h

EAPOL_SRC = eapol/eapol.c

EAPOL_INC = eapol/eapol.h

ACC_SRC = acc/utility.c \
          acc/net.c \
          acc/tun.c \
          acc/db.c \
          acc/nat.c \
          acc/redir.c \
          acc/timer.c \
          acc/dns.c \
          acc/arp.c \
          acc/dhcp.c \
          acc/icmp.c \
          acc/tcp.c \
          acc/subscriber.c \
          acc/radiusC.c \
          acc/md5.c \
          acc/acc.c

ACC_INC = ../inc/type.h \
          ../inc/common.h \
          ../inc/utility.h \
          ../inc/arp.h \
          ../inc/db.h \
          ../inc/dhcp.h \
          ../inc/dns.h \
          ../inc/icmp.h \
          ../inc/nat.h \
          ../inc/net.h \
          ../inc/tcp.h  \
          ../inc/timer.h \
          ../inc/transport.h \
          ../inc/tun.h \
          ../inc/md5.h \
          ../inc/radiusC.h \
          ../inc/redir.h \
          ../inc/subscriber.h \
          ../inc/acc.h

Trench_SOURCES = $(UIDAI_SRC) \
                 $(UAM_SRC) \
                 $(OAUTH20_SRC) \
                 $(EAPOL_SRC) \
                 $(ACC_SRC)
        
Trench_HEADERS = $(UIDAI_INC) \
                 $(UAM_INC) \
                 $(OAUTH20_INC) \
                 $(EAPOL_INC) \
                 $(ACC_INC)
             
Trench_LDFLAGS = $(AM_LDFLAGS)
Trench_LFLAGS = $(AM_LFLAGS)
Trench_CFLAGS = $(AM_CFLAGS)
Trench_CPPFLAGS = $(AM_CPPFLAGS)

LINK = $(LD) -o $@
