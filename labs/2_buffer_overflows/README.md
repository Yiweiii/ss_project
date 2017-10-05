# Buffer-Overflow Vulnerability Lab

This lab is part of the [SEED Labs](http://www.cis.syr.edu/~wedu/seed/). 

Refer to the [lab webpage](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Buffer_Overflow/) for full details.

Needed Files (4): 

- [Description](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Buffer_Overflow/Buffer_Overflow.pdf)
- [`stack.c`](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Buffer_Overflow/files/stack.c)
- [`call_shellcode.sh`](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Buffer_Overflow/files/call_shellcode.c)
- [`exploit.c`](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Buffer_Overflow/files/exploit.c)

# Tips

- You may want to install a plugin for the GDB debugger to assist you. You may want to try `peda`

		cd ~/
		git clone https://github.com/longld/peda.git ~/bin/peda
		echo 'source ~/bin/peda/peda.py' | sudo tee --append ~/.gdbinit > /dev/null

- Before trying to inject shellcode of SEED Labs, start by the simpler exercises `0-simple`, `1-match`, etc. You may want to use the guide [`bo-guide.pdf`](bo-guide.pdf).