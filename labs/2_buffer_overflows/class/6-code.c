// compile 
// sudo gcc 6-code.c -o 6-code -fno-stack-protector -z execstack; sudo chmod 4755 6-code

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  char buffer[128];

  printf("You win this game if you are able to do something other than reaching the end of this function.'\n");

  gets(buffer);
}