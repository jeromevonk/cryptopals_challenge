#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Common for cryptopals
#include "util.h"
#include "crypto_util.h"

// For this challenge only
#define NUMBER_OF_TESTS 100

int encryptUnderUnknowKey(unsigned char* auchPlaintext, unsigned int uiPlaintextLen, unsigned char* auchCiphertext, unsigned int* puiCiphertextLen)
{
   int iMode = -1;

   // Generate a 16-byte key
   Block key(AES_BLOCK_SIZE);
   generateRandomKey(key.data, key.len);

   // Append 5-10 bytes before
   Block randomBefore( (rand() % 6) + 5 );
   generateRandomKey(randomBefore.data, randomBefore.len);

   // Append 5-10 bytes after
   Block randomAfter( (rand() % 6) + 5 );
   generateRandomKey(randomAfter.data, randomAfter.len);

   // Under the hood, append the bytes
   Block newPlaintext(uiPlaintextLen + randomBefore.len + randomAfter.len);

   int iOffset = 0;

   memcpy(&newPlaintext.data[iOffset], randomBefore.data, randomBefore.len);
   iOffset += randomBefore.len;

   memcpy(&newPlaintext.data[iOffset], auchPlaintext,     uiPlaintextLen);
   iOffset += uiPlaintextLen;

   memcpy(&newPlaintext.data[iOffset], randomAfter.data, randomAfter.len);
   iOffset += randomAfter.len;
   
   //printf("\nUnder the hood plaintext is:\n");
   //PrintToConsole(newPlaintext.data, newPlaintext.len, false);

   
   // Which scheme will we use?
   if ( rand() % 2 )
   {
      // Use ECB
      iMode = ECB_MODE;

      AES_ECB_Encrypt(newPlaintext.data, newPlaintext.len, auchCiphertext, puiCiphertextLen, key.data, true);
   }
   else
   {
      // Use CBC
      iMode = CBC_MODE;
      
      // Use a random IV
      Block IV(AES_BLOCK_SIZE);
      generateRandomKey(IV.data, IV.len);

      // Encrypt
      AES_CBC_Encrypt(newPlaintext.data, newPlaintext.len, auchCiphertext, puiCiphertextLen, key.data, IV.data, true);
   }

   return iMode;
}


int main()
{
   printf("|- - - - - - - - - - - - - - -\n");
   printf("|       Detection oracle     |\n");
   printf("|- - - - - - - - - - - - - - -\n");

   srand((unsigned int)time(NULL));

   // ------------------------------------------------------------------------------
   // Read the input
   // ------------------------------------------------------------------------------
#ifdef _test
   Block input(112);
   memcpy(input.data, "ThisIsJustATest!________________________________________________________________________________________________", 112);
#else
   Block input;
   if (!BlockReadFile(&input, "11.jpg"))
   {
      printf("Error reading file\n");
      pause();
      return -1;
   }
#endif

   Block output(input.len + 32 + 16); // give space for padding and extra numbers
   memset(output.data, 0, output.len);

   // ------------------------------------------------------------------------------
   // Perform a bunch of operations
   // ------------------------------------------------------------------------------
   bool bSucceeded = true;
   for (int i = 0; i < NUMBER_OF_TESTS; i++)
   {
      int iMode     = encryptUnderUnknowKey(input.data, input.len, output.data, &output.len);
      int iDetected = detecECBMode(output.data, output.len, 16);

      if ( iMode == iDetected )
      {
         printf(".");
         fflush(stdout);

         //printf("\nCiphertext was:\n");
         //PrintToConsole(output.data, output.len, false, true);
      }
      else
      {
         bSucceeded = false;
         printf("\nProblem: Mode = %d, detected %d", iMode, iDetected);
         printf("\nCiphertext was:\n");
         PrintToConsole(output.data, output.len, false, true);
         pause();
      }
   }

   if ( bSucceeded )
   {
      printf("\n%d tests detecting between ECB or CBC, all suceeded!\n", NUMBER_OF_TESTS);
   }


   pause();

   return 0;
}