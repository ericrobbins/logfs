all: logfs

OUTFILES=logfs

CFLAGS=-g3 -Wall -Wextra -Wno-unused-parameter -D_FILE_OFFSET_BITS=64 -I/usr/include/fuse
LDFLAGS=
LIBS=-leric -lpthread -lfuse -lrt -ldl

logfs: logfs.o 
	gcc $(CFLAGS) -o logfs logfs.o $(LDFLAGS) $(LIBS)

clean:
	rm -f *.o $(OUTFILES)

.c.o:
	gcc -c $(CFLAGS) $<
