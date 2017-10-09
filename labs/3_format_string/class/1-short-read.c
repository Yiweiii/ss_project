// sudo sysctl -w kernel.randomize_va_space=0
// gcc -g -o 1-short-read 1-short-read.c

#include <stdio.h>

int main(int argc, char* argv[]){
	char buffer[12];
	int secret_number=42;
	static char secret_message[12]="COVFEFE";

	printf("***** BEFORE ATTACK *****\n");
	printf("VAR secret_number  : %p %d\n", &secret_number, secret_number);
	printf("VAR secret_message : %p %s\n", &secret_message, secret_message);
	printf("VAR buffer         : %p %s\n", &buffer, buffer);

	fgets(buffer, 12, stdin);
	printf("\nbuffer : ");
	printf(buffer);
	printf("\n");

	printf("***** AFTER ATTACK *****\n");
	printf("VAR secret_number  : %p %d\n", &secret_number, secret_number);
	printf("VAR secret_message : %p %s\n", &secret_message, secret_message);
	printf("VAR buffer         : %p %s\n", &buffer, buffer);
}