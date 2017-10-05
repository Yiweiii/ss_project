#!/bin/bash

clear

sudo apt-get -y -q update
echo "********** INSTALLING Git **********"
sudo apt-get install -y -q git
echo "********** INSTALLING GDB-Peda **********"
cd ~/
git clone https://github.com/longld/peda.git ~/bin/peda
echo 'source ~/bin/peda/peda.py' | sudo tee --append ~/.gdbinit > /dev/null
sudo touch /root/this_is_a_secret_file.txt