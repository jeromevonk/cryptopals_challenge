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

   
   // Read all lines from file
   BlockVector lines = GetLinesFromFile( "08.txt" );
   if ( lines.size() == 0 )
   {
      printf("The file does not exist or could not be opened.");
   }

   int iLine = 0;
   
   // Read line by line
   for (Block const& line_ASC : lines)
   {
      // Keep track of the line number
      iLine++;

      // Convert string to hex
      Block line_Hex = String_to_Hex( line_ASC.data, line_ASC.len );
      if ( line_Hex.len < 0)
      {
         printf("Some error ocurred while converting string to hex\n");
         //return false;
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