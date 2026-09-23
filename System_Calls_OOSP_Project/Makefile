CC = gcc
CFLAGS = -Wall -Wextra -std=c99

all: tracer target

tracer: tracer.c
	$(CC) $(CFLAGS) tracer.c -o tracer

target: target.c
	$(CC) $(CFLAGS) target.c -o target

clean:
	rm -f tracer target