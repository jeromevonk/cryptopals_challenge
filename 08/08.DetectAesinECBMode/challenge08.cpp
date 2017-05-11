#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Common for cryptopals
#include "util.h"
#include "crypto_util.h"


int main()
{
   printf("|- - - - - - - - - - - - - - -\n");
   printf("|    Detect AES in ECB Mode   |\n");
   printf("|- - - - - - - - - - - - - - -\n");

   // Open the file
   FILE* fp = fopen("08.txt", "rb");
   if ( NULL == fp)
   {
      printf("The file does not exist or could not be opened");
      return -1;
   }
   
   Block line_ASC;

   int iLine = 0;
   
   // Read line by line
   while ( 0 != (line_ASC.len = BlockGetLine(fp, &line_ASC)) )
   {
      iLine++;

      // Convert string to hex
      Block line_Hex(line_ASC.len / 2);
      
      line_Hex.len = String_to_Hex( line_ASC.data, line_ASC.len, line_Hex.len, line_Hex.data);
      if ( line_Hex.len < 0)
      {
         printf("Some error ocurred while converting string to hex\n");
         return false;
      }

      // Compare the strings
      int iDetected = detecECBMode(line_Hex.data, line_Hex.len, 16, true);
      if (ECB_MODE == iDetected)
      {
         printf("\nLine %d, detected ECB!\n", iLine);
      }
   }
   
   pause();
  
   return 0;
}