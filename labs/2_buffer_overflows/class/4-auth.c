// compile 
// gcc 4-auth.c -o 4-auth -fno-stack-protector

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int very_complex_function(char* password)
{
  int result;
  char buffer[16];

  result = 0;
  strcpy(buffer, password);

  if(strcmp(buffer, "V3RY53cr37") == 0)
    result = 1;

  return result;
}

int main(int argc, char **argv)
{
  char user[16];
  char password[16];

  if(argc == 1) {
      errx(1, "please specify the user and passwd arguments\n");
  }

  if(very_complex_function(argv[2])){
      printf("Welcome back %s. You have access to our system\n", argv[1]);
  } else {
      printf("Unauthorized user/passwd");
  }
}