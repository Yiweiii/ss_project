# Race-Condition Vulnerability Lab

This lab is part of the [SEED Labs](http://www.cis.syr.edu/~wedu/seed/). 

Refer to the [lab webpage](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Race_Condition/) for full details.

Needed Files (3): 

- [Description](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Race_Condition/Race_Condition.pdf)
- [`vulp.c`](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Race_Condition/files/vulp.c)
- [`check.sh`](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Race_Condition/files/check.sh)

	* Notes1: in `vulp.c` the include of `string.h` is missing; 

# Tips

- Do not forget to compile with the correct permissions

		gcc vulp.c -o vulp && sudo chown root vulp && sudo chmod +s vulp
		
- Do not forget to disable the protection that prevents following a symlink unless the follower and directory owner match the symlink owner. This protection is implemented since Ubuntu 10.10 and protects against (these) race conditions

		sudo sysctl -w kernel.yama.protected_sticky_symlinks=0
		
- Do not forget to add `string.h` to `vulp.c`

		#include <string.h>
		
- You may want to try first your script without trying to win the race. Experiment with file `vulp-v0.c` that sleeps for 3 seconds to give you a vulnerability window between the TOC and TOU. This one is easier to defeat.

- Are you creating the correct symbolic link? Try 

		echo "hello" > /tmp/XYZ

and see if the expected file is being written.

- Notice that if the program `vuln` writes on `/tmp/XYZ` while it has no link to another file then there is no way to win the race. The file `/tmp/XYZ` will then be owned by `root` and you can no longer link (nor unlink) it anywhere.

- Although it is possible to do it with a VM with a single-core, some students reported that they were only able to succeed when having 2-cores assigned to the VM. You may want to give it a try.
