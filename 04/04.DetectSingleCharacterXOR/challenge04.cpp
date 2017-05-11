#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Common for cryptopals
#include "util.h"
#include "crypto_util.h"


int main()
{
   printf("|- - - - - - -\n");
   printf("|  XOR Detect |\n");
   printf("|- - - - - - -\n");
   

   FILE* fp = fopen("04.txt", "rb");
   if (NULL == fp)
   {
      printf("The file does not exist or could not be opened");
      return -1;
   }

   int iBestScore = 0;
   int iTempScore = 0;
   int iLine = 0;

   Block line_ASC(60);
   Block tempPlaintext;
   Block bestPlaintext;

   char chBestChar;
   int  iBestLine;

   // Read line by line
   while ( 0 != (line_ASC.len = GetLine(line_ASC.data, 60, fp) ) ) 
   {
      iLine++;

      // Convert string to hex
      Block line_hex;
      line_hex.alloc(line_ASC.len/2);

      int iTemp = String_to_Hex(line_ASC.data, line_ASC.len, line_hex.len, line_hex.data);
      if (iTemp < 0)
      {
         printf("Some error ocurred while converting string to hex\n");
         //return false;
      }
      else
      {
         line_hex.len = iTemp;
      }

      // Let's XOR the string against 0xFF characters
      for (int i = 0; i < 256; i++)
      {
         tempPlaintext = line_hex;
         XOR_string(tempPlaintext.data, tempPlaintext.len, (unsigned char)i);

         // Give it a score
         iTempScore = scoreBlock(tempPlaintext.data, tempPlaintext.len);

         if (iTempScore > iBestScore)
         {
            iBestScore = iTempScore;
            chBestChar = i;
            iBestLine  = iLine;
            
            // Copy the best plaintext
            bestPlaintext = tempPlaintext;
         }
      }
   }

   printf("Line %d has been encrypted with single-character XOR against char 0x%02X ('%c')\n", iBestLine, chBestChar, chBestChar);
   printf("Decrypted line is: ");
   PrintToConsole(bestPlaintext.data, bestPlaintext.len);
   
   pause();
   
   return 0;
}