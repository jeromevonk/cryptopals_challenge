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

   // Read all lines from file
   BlockVector lines = GetLinesFromFile( "04.txt" );
   if ( lines.size() == 0 )
   {
      printf("The file does not exist or could not be opened.");
   }

   int iBestScore = 0;
   int iTempScore = 0;
   int iLine = 0;
   
   Block tempPlaintext;
   Block bestPlaintext;

   char chBestChar;
   int  iBestLine;

   // Read line by line
   for (Block const& line_ASC : lines)
   {
      // Keep track of the line number
      iLine++;

      // Convert string to hex
      Block line_hex = String_to_Hex(line_ASC.data, line_ASC.len);
      if (line_hex.len < 0)
      {
         printf("Some error ocurred while converting string to hex\n");
         //return false;
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