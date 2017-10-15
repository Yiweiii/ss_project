# Format Strings Vulnerability Lab

For this lab we propose a series of simple exercises `0-read.c` to `4-return.c`.

Then, we propose a more complex task that is part of the [SEED Labs Project](http://www.cis.syr.edu/~wedu/seed/). 
Refer to the [lab webpage](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Format_String/) for full details. In the end of this lab session you are supposed to be able to complete Task~1 of this.

Needed Files (4): 

- Simple exercises `0-read.c` to `4-return.c`
- [Description of SEED Labs Sormat Strings lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Format_String/Format_String.pdf)
- [`vul_prog.c`](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Format_String/files/vul_prog.c)
- [`write_string.c`](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Format_String/files/write_string.c)


# Tips

- Before trying to do the SEED Labs examples, you may want to start with the basic exploit exercises `0-read.c` until `4-return.c`. These go from simply reading values from the stack, to change return addresses and redirect control-flow. Below you can find some tips and instructions.

- If you have not done it for the [buffer overflow lab](../buffer_overflow_lab), you may want to install a plugin for the GDB debugger to assist you. You may want to try `peda`

		cd ~/
		git clone https://github.com/longld/peda.git ~/bin/peda
		echo 'source ~/bin/peda/peda.py' | sudo tee --append ~/.gdbinit > /dev/null

- Notice that these files do not need to be compiled with `-fno-stack-protector` nor `-z execstack` but you need to disable the ASLR for all of them (this is global for the OS)

		echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

Compilation info is at the header of each source file.

0. Start with exercise [`0.read.c`](0-read.c). Compile it and notice that in this case you cannot do a buffer overflow as `buffer` is located __below__ the other variables. In fact `secret_message` is even in a different memory segment. 

	* Can you still read `secret_number`? 
	* And `secret_message`? 

The `printf`s are there just to help you and you should be able to get these values in some other way.

1. And if you have a shorter buffer of 12-bytes? Can you still read ___both___ these values? Try it with [`1-short-read.c`](1-short-read.c)

2. Function `printf` also allows you to write on variables using the format string `%n`.

	* Can you change the value of `integrity_number` in [`2-write.c`](2-write.c)?
	* Can you change it to `100`?
	* Can you change the `integrity_message` to `A`?

3. [`3-functions.c`](3-functions.c) looks like buffer-overflow again but in this case `buffer` is located __below__ `fp`. Can you still win the game?

4. And what about [`4-return.c`](4-return.c)? Can you still win the game **even** with stack protection enabled?