# Buffer-Overflow Vulnerability Lab

For this lab we propose a series of simple exercises `0-simple.c` to `7-environment.c` that were adapted from the [Exploit Exercises Project](https://exploit-exercises.com/) namely the [Protostar Project](https://exploit-exercises.com/protostar/) and from the book ___Hacking, The Art of Exploitation___ by Jon Erickson.

Then, we propose a more complex task to inject shellcode that is part of the [SEED Labs Project](http://www.cis.syr.edu/~wedu/seed/). 
Refer to the [lab webpage](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Buffer_Overflow/) for full details. In the end of this lab session you are supposed to be able to complete Task~1 of this.

Needed Files (4): 

- [Description of simple exercises](bo-guide.pdf)
- Simple exercises `0-simple.c` to `7-environment.c`
- [Description of SEED Labs BO lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Buffer_Overflow/Buffer_Overflow.pdf)
- [`stack.c`](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Buffer_Overflow/files/stack.c)
- [`call_shellcode.sh`](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Buffer_Overflow/files/call_shellcode.c)
- [`exploit.c`](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Buffer_Overflow/files/exploit.c)

	* Notes1: in `call_shellcode.c` the include of `string.h` is missing; 
	* Notes2: in `stack.c` the buffer must be 32 bytes instead of 24

# Tips

- You may want to install a plugin for the GDB debugger to assist you. You may want to try `peda`

		cd ~/
		git clone https://github.com/longld/peda.git ~/bin/peda
		echo 'source ~/bin/peda/peda.py' | sudo tee --append ~/.gdbinit > /dev/null

- Before trying to inject shellcode of the SEED Labs, you may want to start with the basic exploit exercises `0-simple.c` until `7-environment.c`. These go from simple buffer-overflow, to change return addresses, redirect control-flow, shell-code injection, and exploitation of environment variables. Look at the file [`bo-guide.pdf`](bo-guide.pdf) for tips and instructions.

- Notice that some of these files need to be compiled with `-fno-stack-protector` and others with `-z execstack`. This info is at the header of each source file.

- Also, disable the ASLR for all of them (this is global for the OS)

		echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

 - Are you getting `0xXXYYZZWW` instead of `0xWWZZYYXX`? Recall big and little-endian.

- ***Notice*** that solutions differ according to the architectures.

## Shell-code

- File `test_shellcode-32.c` has some examples of shellcode.
You can test them by uncommenting the corresponding line and compiling as

		gcc test-shellcode-32.c -o test-shellcode -fno-stack-protector -z execstack; chmod 4755 test-shellcode; ./test-shellcode

