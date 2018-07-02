#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Common for cryptopals
#include "util.h"
#include "crypto_util.h"


Block encryptSecretKey(unsigned char* auchPlaintext, unsigned int uiPlaintextLen)
{
   // Fixed, secret key
   unsigned char auchKey[16] = { 0xAF, 0x89, 0x83, 0x29, 0x08, 0xD7, 0xF8, 0x97, 0x24, 0x89, 0xF7, 0x28, 0x9F, 0x78, 0x9E, 0x15 };

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

   // Decode the string
   Block toAppend_hex = base64decode(toAppend, sizeof(toAppend));

   // Append the bytes
   Block newPlaintext(uiPlaintextLen + toAppend_hex.len);

   // This block will be returned by the function
   Block ciphertext( getPKCS7paddedSize(newPlaintext.len, AES_BLOCK_SIZE) );

   int iOffset = 0;

   memcpy(&newPlaintext.data[iOffset], auchPlaintext, uiPlaintextLen);
   iOffset += uiPlaintextLen;

   memcpy(&newPlaintext.data[iOffset], toAppend_hex.data, toAppend_hex.len);
   iOffset += toAppend_hex.len;

   // Perform the encryption
   AES_ECB_Encrypt(newPlaintext.data, newPlaintext.len, ciphertext.data, &ciphertext.len, auchKey, true);

   return ciphertext;
}

int main()
{
   printf("|- - - - - - - - - - - - - - - - - -\n");
   printf("|   Byte-at-a-time ECB Decryption   |\n");
   printf("|- - - - - - - - - - - - - - - - - -\n");

   // 1) Discover the block size of the cipher
   Block tst_input;

   unsigned int uiMinLen = -1; // set the highest possible value as starting value
   unsigned int uiMaxLen = 0;  // set the lowest  possible value as starting value

   unsigned int uiBlockSize = 0;
   unsigned int uiSufixLen  = 0;

   // Must run the algorithm at least 17 times, to get when the number of blocks increase
   for (int i = 1; i <= 17; i++)
   {
      tst_input.alloc(i);
      tst_input.set_to( 'A' );

      Block tst_output = encryptSecretKey(tst_input.data, tst_input.len);

      if ( tst_output.len < uiMinLen )
      {
         uiMinLen = tst_output.len;
      }

      if (tst_output.len > uiMaxLen)
      {
         uiMaxLen = tst_output.len;
         uiSufixLen = tst_output.len - i - 16;
      }
   }

   uiBlockSize = uiMaxLen - uiMinLen;
   printf("The block size of the cipher is %d.\n", uiBlockSize);
   printf("The length of the sufix is %d.\n", uiSufixLen);


   // 2) Discover the mode of operation
   Block input(64);
   input.set_to_zeroes();

   Block output = encryptSecretKey(input.data, input.len);

   int iDetected = detecECBMode(output.data, output.len, uiBlockSize);
   printf("Block cipher mode is %s\n", iDetected == ECB_MODE ? "ECB" : "CBC");

   // 3) Discover the bytes
   // -----------------------------------------------------------------------------
   // Approach: Craft a block which is 1 byte short. That way, the oracle 
   //           function will concat the first bytes of the secret string to
   //           complete a block. 
   //           Then, feed the oracle with all the possible values for the missing
   //           byte and compare the results with the one-byte-short output
   //           After you discover some bytes, feed the oracle with blocks
   //           according to the following fashion:
   // 
   //           (where A = controlled by attacker, B = byte discovered from the string,
   //            X= next byte to be discovered)
   //
   //           1st  byte: AAAAAAAAAAAAAAAX     
   //           2nd  byte: AAAAAAAAAAAAAABX 
   //           3rd  byte: AAAAAAAAAAAAABBX 
   //           15th byte: ABBBBBBBBBBBBBBX 
   //           16th byte: BBBBBBBBBBBBBBBX 
   //
   //           (now, two blocks are needed)
   //           17th byte: AAAAAAAAAAAAAAAB BBBBBBBBBBBBBBBX
   //           18th byte: AAAAAAAAAAAAAABB BBBBBBBBBBBBBBBX
   //           19th byte: AAAAAAAAAAAAABBB BBBBBBBBBBBBBBBX
   //           31th byte: ABBBBBBBBBBBBBBB BBBBBBBBBBBBBBBX
   //           32th byte: BBBBBBBBBBBBBBBB BBBBBBBBBBBBBBBX
   //
   //           (now, three blocks are needed)
   //           33th byte: AAAAAAAAAAAAAAAB BBBBBBBBBBBBBBBB BBBBBBBBBBBBBBBX
   //           34th byte: AAAAAAAAAAAAAABB BBBBBBBBBBBBBBBB BBBBBBBBBBBBBBBX
   //           35th byte: AAAAAAAAAAAAABBB BBBBBBBBBBBBBBBB BBBBBBBBBBBBBBBX
   //           47th byte: ABBBBBBBBBBBBBBB BBBBBBBBBBBBBBBB BBBBBBBBBBBBBBBX
   //           48th byte: BBBBBBBBBBBBBBBB BBBBBBBBBBBBBBBB BBBBBBBBBBBBBBBX
   //
   //           and so on!
   //
   // Complexity: 138 * 256
   // -----------------------------------------------------------------------------
   
   // Need a couple blocks for testing
   Block one_byte_short;
   Block tst_against;
   Block secret_data(uiSufixLen);

   printf("Decrypting the unknown string");
   fflush(stdout);

   for (unsigned i = 0; i < secret_data.len; i++)
   {
      // Craft an input block that is exactly 1 byte less than the blocksize
      one_byte_short.alloc( (i/ uiBlockSize)*uiBlockSize + uiBlockSize );

      memset(one_byte_short.data, 'A', one_byte_short.len - 1 -i );
      //memcpy(&one_byte_short.data[one_byte_short.len - i - 1], secret_data.data, i);

      Block one_byte_short_output = encryptSecretKey(one_byte_short.data, (one_byte_short.len -1 - i));

      // Test against all possibilities
      tst_against.alloc( (i / uiBlockSize) * uiBlockSize + uiBlockSize );

      for (int j = 0; j < 256; j++)
      {
         memset(tst_against.data, 'A', tst_against.len - 1 - i);
         memcpy(&tst_against.data[tst_against.len - i - 1], secret_data.data, i);
         tst_against.data[tst_against.len - 1] = j;

         Block tst_against_output = encryptSecretKey(tst_against.data, tst_against.len);

         if (0 == memcmp(one_byte_short_output.data, tst_against_output.data, tst_against.len))
         {
            secret_data.data[i] = j;
            //printf("Byte number %02d is %#02X - '%c'\n", i, secret_data.data[i], secret_data.data[i]);
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