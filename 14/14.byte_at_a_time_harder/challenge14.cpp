#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Common for cryptopals
#include "util.h"
#include "crypto_util.h"

#define SECRET_STRING_SIZE  138
#define MAXIMUM_PREPEND_SIZE 32


int encryptSecretKey(unsigned char* auchPlaintext, unsigned int uiPlaintextLen, Block* ciphertext)
{
   // Fixed, secret key
   unsigned char auchKey[16] = { 0xAF, 0x89, 0x83, 0x29, 0x08, 0xD7, 0xF8, 0x97, 0x24, 0x89, 0xF7, 0x28, 0x9F, 0x78, 0x9E, 0x15 };

   // Content to prepend is random
   unsigned char toPrepend[32] = { 0xF1, 0x72, 0x38, 0x4F, 0x18, 0x92, 0x37, 0xF4, 0x12, 0x38, 0x7F, 0x41, 0x20, 0x37, 0xF4, 0x12,
                                   0x3F, 0x71, 0x40, 0x23, 0xF7, 0xF7, 0x12, 0x89, 0x34, 0x71, 0x23, 0x31, 0x9F, 0xF1, 0x71, 0xB3 };

   // String to be appended
   unsigned char toAppend[184] = {
      0x55, 0x6D, 0x39, 0x73, 0x62, 0x47, 0x6C, 0x75, 0x4A, 0x79, 0x42, 0x70,
      0x62, 0x69, 0x42, 0x74, 0x65, 0x53, 0x41, 0x31, 0x4C, 0x6A, 0x41, 0x4B,
      0x56, 0x32, 0x6C, 0x30, 0x61, 0x43, 0x42, 0x74, 0x65, 0x53, 0x42, 0x79,
      0x59, 0x57, 0x63, 0x74, 0x64, 0x47, 0x39, 0x77, 0x49, 0x47, 0x52, 0x76,
      0x64, 0x32, 0x34, 0x67, 0x63, 0x32, 0x38, 0x67, 0x62, 0x58, 0x6B, 0x67,
      0x61, 0x47, 0x46, 0x70, 0x63, 0x69, 0x42, 0x6A, 0x59, 0x57, 0x34, 0x67,
      0x59, 0x6D, 0x78, 0x76, 0x64, 0x77, 0x70, 0x55, 0x61, 0x47, 0x55, 0x67,
      0x5A, 0x32, 0x6C, 0x79, 0x62, 0x47, 0x6C, 0x6C, 0x63, 0x79, 0x42, 0x76,
      0x62, 0x69, 0x42, 0x7A, 0x64, 0x47, 0x46, 0x75, 0x5A, 0x47, 0x4A, 0x35,
      0x49, 0x48, 0x64, 0x68, 0x64, 0x6D, 0x6C, 0x75, 0x5A, 0x79, 0x42, 0x71,
      0x64, 0x58, 0x4E, 0x30, 0x49, 0x48, 0x52, 0x76, 0x49, 0x48, 0x4E, 0x68,
      0x65, 0x53, 0x42, 0x6F, 0x61, 0x51, 0x70, 0x45, 0x61, 0x57, 0x51, 0x67,
      0x65, 0x57, 0x39, 0x31, 0x49, 0x48, 0x4E, 0x30, 0x62, 0x33, 0x41, 0x2F,
      0x49, 0x45, 0x35, 0x76, 0x4C, 0x43, 0x42, 0x4A, 0x49, 0x47, 0x70, 0x31,
      0x63, 0x33, 0x51, 0x67, 0x5A, 0x48, 0x4A, 0x76, 0x64, 0x6D, 0x55, 0x67,
      0x59, 0x6E, 0x6B, 0x4B
   };

   // Since the string to be appended do not change, perform the base64 decoding only once
   static Block toAppend_hex;
   if (0 == toAppend_hex.len)
   {
      // Base64 decode it
      int iMaximumSize = sizeof(toAppend) * 3 / 4;
      toAppend_hex.alloc(iMaximumSize);
      toAppend_hex.len = base64decode(toAppend, sizeof(toAppend), toAppend_hex.data, iMaximumSize);
   }

   // The length of the prefix will be random
   static unsigned int uiRandomLength = 0; 
   if ( 0 == uiRandomLength )
   {
      // Should be here only once by execution
      srand((unsigned int)time(NULL));
      uiRandomLength = (rand() % 32) + 1;
   }

   // Prepend/append the bytes
   Block newPlaintext(uiRandomLength + uiPlaintextLen + toAppend_hex.len);
   ciphertext->alloc(getPKCS7paddedSize(newPlaintext.len, AES_BLOCK_SIZE));

   int iOffset = 0;

   memcpy(&newPlaintext.data[iOffset], toPrepend, uiRandomLength);
   iOffset += uiRandomLength;

   memcpy(&newPlaintext.data[iOffset], auchPlaintext, uiPlaintextLen);
   iOffset += uiPlaintextLen;

   memcpy(&newPlaintext.data[iOffset], toAppend_hex.data, toAppend_hex.len);
   iOffset += toAppend_hex.len;

   // Perform the encryption
   AES_ECB_Encrypt(newPlaintext.data, newPlaintext.len, ciphertext->data, &ciphertext->len, auchKey, true);

   return 0;
}


int main()
{
   printf(" - - - - - - - - - - - - - - - - - - - - - -\n");
   printf("|   Byte-at-a-time ECB Decryption (harder)  |\n");
   printf(" - - - - - - - - - - - - - - - - - - - - - -\n");

   // 1) Discover the block size of the cipher and the size of the random-prefix
   Block tst_input;
   Block tst_output;

   unsigned int uiMinLen = -1; // set the highest possible value as starting value
   unsigned int uiMaxLen = 0;  // set the lowest  possible value as starting value

   unsigned int uiBlockSize = 0;
   unsigned int uiPrefixLen = 0;

   // Must run the algorithm at least 17 times, to get when the number of blocks increase
   for (int i = 1; i <= 17; i++)
   {
      tst_input.alloc(i);
      memset(tst_input.data, 'A', i);

      encryptSecretKey(tst_input.data, tst_input.len, &tst_output);

      if ( tst_output.len < uiMinLen )
      {
         uiMinLen = tst_output.len;
      }

      if (tst_output.len > uiMaxLen)
      {
         uiMaxLen    = tst_output.len;
         uiPrefixLen = tst_output.len - SECRET_STRING_SIZE - i - 16; // is it possible to unravel the SECRET_STRING_SIZE programmatically?
      }
   }

   uiBlockSize = uiMaxLen - uiMinLen;
   printf("The block size of the cipher is %d.\n", uiBlockSize);
   printf("The length of the prefix is %d.\n", uiPrefixLen);


   // 2) Discover the mode of operation
   Block input(64);
   input.set_to_zeroes();

   Block output(input.len + MAXIMUM_PREPEND_SIZE + SECRET_STRING_SIZE + 16); // give space for padding and string appended

   encryptSecretKey(input.data, input.len, &output);
   int iDetected = detecECBMode(output.data, output.len, uiBlockSize);
   printf("Block cipher mode is %s\n", iDetected == ECB_MODE ? "ECB" : "CBC");



   // 3) Discover the bytes
   // -----------------------------------------------------------------------------
   // Approach: Since we know the prefix length, we must craft and additional
   //           filler so that the prefix + filler will fit in one or more FULL blocks
   //           After that, craft a block which is 1 byte short. That way, the oracle 
   //           function will concat the first bytes of the secret string to
   //           complete a block. 
   //           Then, feed the oracle with all the possible values for the missing
   //           byte and compare the results with the one-byte-short output
   //           After you discover some bytes, feed the oracle with blocks
   //           according to the following fashion:
   // 
   //           (where P = prefix, F= filler, A = controlled by attacker, 
   //            B = byte discovered from the string, X= next byte to be discovered)
   //
   //           Example supposing a prefix with length of 26 ==> filler length 6
   //
   //           1st  byte: PPPPPPPPPPPPPPPP PPPPPPPPPPFFFFFF AAAAAAAAAAAAAAAX     
   //           2nd  byte: PPPPPPPPPPPPPPPP PPPPPPPPPPFFFFFF AAAAAAAAAAAAAABX 
   //           3rd  byte: PPPPPPPPPPPPPPPP PPPPPPPPPPFFFFFF AAAAAAAAAAAAABBX 
   //           15th byte: PPPPPPPPPPPPPPPP PPPPPPPPPPFFFFFF ABBBBBBBBBBBBBBX 
   //           16th byte: PPPPPPPPPPPPPPPP PPPPPPPPPPFFFFFF BBBBBBBBBBBBBBBX 
   //
   //           (now, two crafted blocks are needed)
   //           17th byte: PPPPPPPPPPPPPPPP PPPPPPPPPPFFFFFF AAAAAAAAAAAAAAAB BBBBBBBBBBBBBBBX
   //           18th byte: PPPPPPPPPPPPPPPP PPPPPPPPPPFFFFFF AAAAAAAAAAAAAABB BBBBBBBBBBBBBBBX
   //           19th byte: PPPPPPPPPPPPPPPP PPPPPPPPPPFFFFFF AAAAAAAAAAAAABBB BBBBBBBBBBBBBBBX
   //           31th byte: PPPPPPPPPPPPPPPP PPPPPPPPPPFFFFFF ABBBBBBBBBBBBBBB BBBBBBBBBBBBBBBX
   //           32th byte: PPPPPPPPPPPPPPPP PPPPPPPPPPFFFFFF BBBBBBBBBBBBBBBB BBBBBBBBBBBBBBBX
   //
   //           (now, three crafted blocks are needed)
   //           33th byte: PPPPPPPPPPPPPPPP PPPPPPPPPPFFFFFF AAAAAAAAAAAAAAAB BBBBBBBBBBBBBBBB BBBBBBBBBBBBBBBX
   //           34th byte: PPPPPPPPPPPPPPPP PPPPPPPPPPFFFFFF AAAAAAAAAAAAAABB BBBBBBBBBBBBBBBB BBBBBBBBBBBBBBBX
   //           35th byte: PPPPPPPPPPPPPPPP PPPPPPPPPPFFFFFF AAAAAAAAAAAAABBB BBBBBBBBBBBBBBBB BBBBBBBBBBBBBBBX
   //           47th byte: PPPPPPPPPPPPPPPP PPPPPPPPPPFFFFFF ABBBBBBBBBBBBBBB BBBBBBBBBBBBBBBB BBBBBBBBBBBBBBBX
   //           48th byte: PPPPPPPPPPPPPPPP PPPPPPPPPPFFFFFF BBBBBBBBBBBBBBBB BBBBBBBBBBBBBBBB BBBBBBBBBBBBBBBX
   //
   //           and so on!
   //
   // Complexity: 138 * 256
   // -----------------------------------------------------------------------------
   
   Block one_byte_short;
   Block one_byte_short_output;

   Block tst_against;
   Block tst_against_output;

   Block secret_data(SECRET_STRING_SIZE);
   
   Block filler(uiBlockSize - (uiPrefixLen%uiBlockSize));

   printf("Decrypting the unknown string");
   fflush(stdout);

   for (unsigned i = 0; i < secret_data.len; i++)
   {
      // Craft an input block that is exactly 1 byte less than the blocksize
      one_byte_short.alloc(filler.len + (i/ uiBlockSize)*uiBlockSize + uiBlockSize );

      memset(one_byte_short.data, 'A', one_byte_short.len - 1 -i );

      encryptSecretKey(one_byte_short.data, (one_byte_short.len -1 - i), &one_byte_short_output);

      // Test against all possibilities
      tst_against.alloc(filler.len + (i / uiBlockSize) * uiBlockSize + uiBlockSize );

      // We won't test against the whole ciphertext. Find the block to be tested against (always the last block we crafted)
      unsigned int uiAddress = uiPrefixLen + filler.len + (i / uiBlockSize) * uiBlockSize;

      for (int j = 0; j < 256; j++)
      {
         memset(tst_against.data, 'A', tst_against.len - 1 - i);
         memcpy(&tst_against.data[tst_against.len - i - 1], secret_data.data, i);
         tst_against.data[tst_against.len - 1] = j;

         encryptSecretKey(tst_against.data, tst_against.len, &tst_against_output);

         if (0 == memcmp(&one_byte_short_output.data[uiAddress], &tst_against_output.data[uiAddress], uiBlockSize))
         {
            secret_data.data[i] = j;
            printf(".");
            fflush(stdout);
         }
      }
   }

   // Print the answer to the challenge
   printf("\n\nThe secret string is:\n");
   PrintToConsole(secret_data.data, secret_data.len);

   pause();

   return 0;
}