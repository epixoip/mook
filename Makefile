CXX=g++
CFLAGS=-Wall -g -O2
OUT=mook
OBJS=iface.o ports.o main.o
LDFLAGS=
LIBS=-lpcap

PREFIX=/usr
BINDIR=/bin

all: $(OBJS)
	$(CXX) $(CFLAGS) -o $(OUT) $(LDFLAGS) $(OBJS) $(LIBS)

iface.o:
	$(CXX) -c $(CFLAGS) -o iface.o iface.cpp

ports.o:
	$(CXX) -c $(CFLAGS) -o ports.o ports.cpp

main.o:
	$(CXX) -c $(CFLAGS) -o main.o main.cpp

install:
	install -m 0755 -o root -d $(DESTDIR)$(PREFIX)$(BINDIR)
	install -m 0755 -o root $(OUT) $(DESTDIR)$(PREFIX)$(BINDIR)

clean:
	rm -f $(OUT) $(OBJS)
