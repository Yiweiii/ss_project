/*  vulp.c  */

#include <stdio.h>
#include <unistd.h>
#include <string.h>


int main()
{
   char * fn = "/tmp/XYZ";
   char buffer[60];
   FILE *fp;

   /* get user input */
   scanf("%50s", buffer );

   if(!access(fn, W_OK)){
        sleep(3);
        
        printf("\nRECEIVED STRING: %s\n", buffer);

        fp = fopen(fn, "a+");
        printf("\nOpened file: %s\n", fn);

        fwrite(buffer, sizeof(char), strlen(buffer), fp);
        printf("\nWrote to file-1: %s\n", fn);
        
        fwrite("\n", sizeof(char), 1, fp);
        printf("\nWrote to file-2: %s\n", fn);
        
        fclose(fp);
   }
   else printf("No permission \n");
}
