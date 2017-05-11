#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Common for cryptopals
#include "util.h"
#include "crypto_util.h"

// Defines for this challenge
#define MAX_KEYSIZE 40


int guess_KeySize(unsigned char* auchCryptogram, int iLen)
{
   //int iNumOfSamples    = iLen/MAX_KEYSIZE;
   int iNumOfSamples    = 3;
   int iProbableKeySize = 0;

   float fSmallestDistance = 100;
   for (int i = 3; i <= MAX_KEYSIZE; i++)
   {
      int iDistance = 0;
      for (int j = 0; j < iNumOfSamples; j++ )
      {
         iDistance = hammingDistance(&auchCryptogram[j*i], &auchCryptogram[(j+1)*i], i);
      }

      float fNormalizedDistance = (float)iDistance / iNumOfSamples / i;
      
      //printf("The normalized hamming distance for keysize = %d is %f\n", i, fNormalizedDistance );
      if ( fNormalizedDistance < fSmallestDistance )
      {
         iProbableKeySize  = i;
         fSmallestDistance = fNormalizedDistance;
      }
   }

   return iProbableKeySize;
}


unsigned char discover_key_byte(unsigned char* auchCryptogram, int iCryptogramLen, int iByteToDiscover, int iKeylen)
{
   // ----------------------------------------------------------------------------------------------------------
   // If the keysize is x, divide the ciphertext in x blocks 
   // The length of the block will be either (iCryptogramLen/iKeylen) or (iCryptogramLen/iKeylen)+1
   // The actual size is (iCryptogramLen / iKeylen) + ( (iByteToDiscover < iCryptogramLen%iKeylen) ? 1 : 0 ) ;
   // ----------------------------------------------------------------------------------------------------------
   int iBlockLen = (iCryptogramLen / iKeylen) + ((iByteToDiscover < iCryptogramLen%iKeylen) ? 1 : 0);

   Block considered_block(iBlockLen);
   Block test_block(iBlockLen);

   int iOffset = 0;

   for (int i = iByteToDiscover; i < iCryptogramLen; i += iKeylen)
   {
      considered_block.data[iOffset++] = auchCryptogram[i];
   }

   // Evaluate for every possible character
   unsigned char ucBestByte = 0;
   int iBestScore           = 0;
   for (int k = 0; k < 256; k++)
   {
      // XOR the string against the character
      XOR_encrypt(considered_block.data, considered_block.len, (unsigned char*)&k, 1, test_block.data);

      // Give a score
      int iScore = scoreBlock(test_block.data, test_block.len);

      if ( iScore > iBestScore ) 
      {
         iBestScore = iScore;
         ucBestByte = k;
      }
   }

   return ucBestByte;
}


int main()
{
   printf("|- - - - - - - - - - - - - - -\n");
   printf("|    Break repeating-key XOR  |\n");
   printf("|- - - - - - - - - - - - - - -\n");

   // ------------------------------------------------------------------------------
   // Read the input file
   // ------------------------------------------------------------------------------
   Block base64Text;
   if (!BlockReadFile(&base64Text, "06.txt"))
   {
      printf("Error reading file\n");
      pause();
      return -1;
   }

   // Base64 decode the input 
   int iMaximumSize = base64Text.len *3 / 4;
   
   Block HexBuffer;
   HexBuffer.alloc(iMaximumSize);
   HexBuffer.len = base64decode(base64Text.data, base64Text.len, HexBuffer.data, iMaximumSize);
   
   // -----------------------------------------------------------------------------
   // Approach no 1: guess the keysize, divide the ciphertext in 'keysize' blocks
   //                and for each block find out the byte that gives the best
   //                character frequency.
   //
   // Complexity: KeySize * 256
   // Worst case: 40 * 256
   // -----------------------------------------------------------------------------
   printf("\n--- Approach no. 1 ---\n");
   {
      // Guess the keysize
      Block key;
      key.alloc( guess_KeySize(HexBuffer.data, HexBuffer.len) );
      printf("\tKey size is probably %d\n", key.len);

      // Discover each byte of the key
      for (unsigned i = 0; i < key.len; i++)
      {
         key.data[i] = discover_key_byte(HexBuffer.data, HexBuffer.len, i, key.len);
      }

      // Print the key
      printf("\tThe key has %d bytes and it is:\n\t", key.len);
      PrintToConsole(key.data, key.len);

      // Print the cracked message
      Block plaintext;
      plaintext.alloc(HexBuffer.len);
      XOR_encrypt(HexBuffer.data, HexBuffer.len, key.data, key.len, plaintext.data);
      
      printf("\n\n\tThe message is:\n");
      PrintToConsole(plaintext.data, plaintext.len);
   }
   
   // -----------------------------------------------------------------------------
   // Approach no 2: try all keysizes in the range of 2 to MAX_KEYSIZE
   //                for each keysize, apply approach no 1 to find a key
   //                than compare the MAX_KEYSIZE keys to find the one 
   //                that gives the best plaintext
   //
   // Complexity: 40 * 40 * 256
   // -----------------------------------------------------------------------------
   printf("\n--- Approach no. 2 ---\n");
   {
      Block bestKey;
      Block tempKey;
      
      Block bestPlaintext;
      Block tempPlaintext;
      
      int iBestScore = 0;
      int iTempScore = 0;
      
      for (int iKeySize = 2; iKeySize < MAX_KEYSIZE; iKeySize++ )
      {
         // Allocate the key appropriately
         tempKey.alloc(iKeySize);
         
         // Discover each byte of the key
         for (unsigned i = 0; i < tempKey.len; i++)
         {
            tempKey.data[i] = discover_key_byte(HexBuffer.data, HexBuffer.len, i, tempKey.len);
         }
         
         // Get a plaintext
         tempPlaintext.alloc(HexBuffer.len);
         XOR_encrypt(HexBuffer.data, HexBuffer.len, tempKey.data, tempKey.len, tempPlaintext.data);
         
         // Give it a score
         iTempScore = scoreBlock(tempPlaintext.data, tempPlaintext.len);
         
         if ( iTempScore > iBestScore )
         {
            iBestScore    = iTempScore;
            
            // Copy bestKey
            bestKey       = tempKey; 
            
            // Copy bestPlaintext
            bestPlaintext = tempPlaintext;
         }  
         
         // free the key buffer and plaintext
         tempKey.free();
         tempPlaintext.free();
      }
      
      printf("\t The best key len is %d and it is: \n", bestKey.len);
      PrintToConsole(bestKey.data, bestKey.len);
      
      printf("\n\n\tThe message is:\n");
      PrintToConsole(bestPlaintext.data, bestPlaintext.len);
   }

   pause();

   return 0;
}