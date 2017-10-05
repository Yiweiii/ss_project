// compile 
// gcc 7-environment.c -o 7-environment -fno-stack-protector -z execstack

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  char buffer[16];

  printf("You win this game if you are able to do something other than reaching the end of this function.'\n");

  gets(buffer);
}