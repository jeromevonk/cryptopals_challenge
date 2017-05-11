#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Common for cryptopals
#include "util.h"
#include "crypto_util.h"

unsigned char auchCiphertext[34] = {
   0x1B, 0x37, 0x37, 0x33, 0x31, 0x36, 0x3F, 0x78, 0x15, 0x1B, 0x7F, 0x2B,
   0x78, 0x34, 0x31, 0x33, 0x3D, 0x78, 0x39, 0x78, 0x28, 0x37, 0x2D, 0x36,
   0x3C, 0x78, 0x37, 0x3E, 0x78, 0x3A, 0x39, 0x3B, 0x37, 0x36
};


int main()
{
   printf(" - - - - - - -\n");
   printf("|  XOR Detect |\n");
   printf(" - - - - - - -\n");

   int iBestScore = 0;
   int iTempScore = 0;

   Block tempPlaintext(sizeof(auchCiphertext));
   
   Block bestPlaintext;
   char chBestChar;

   // Let's XOR the string against 0xFF characters
   for (int i = 0; i < 256; i++)
   {
      memcpy(tempPlaintext.data, auchCiphertext, sizeof(auchCiphertext));
      XOR_string(tempPlaintext.data, tempPlaintext.len, (unsigned char)i);

      // Give it a score
      iTempScore = scoreBlock(tempPlaintext.data, tempPlaintext.len);

      if (iTempScore > iBestScore)
      {
         iBestScore = iTempScore;
         chBestChar = i;
            
         // Copy the best plaintext
         bestPlaintext = tempPlaintext;
      }
   }

   printf("String has been encrypted with single-character XOR against char 0x%02X ('%c')\n", chBestChar, chBestChar);
   printf("Decrypted string is: ");
   PrintToConsole(bestPlaintext.data, bestPlaintext.len);
   
   pause();
   
   return 0;
}