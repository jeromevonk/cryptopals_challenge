#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Common for cryptopals
#include "util.h"
#include "crypto_util.h"

// Globals for this challenge
unsigned char auchServerKey[16] = { 0xAF, 0x89, 0x83, 0x29, 0x08, 0xD7, 0xF8, 0x97, 0x24, 0x89, 0xF7, 0x28, 0x9F, 0x78, 0x9E, 0x15 };

BlockVector getPlaintexts( )
{
   // Create an empty vector
   BlockVector out;

   // Read all lines from file
   BlockVector lines = GetLinesFromFile( "20.txt" );
   if ( lines.size() == 0 )
   {
      printf("The file does not exist or could not be opened. Aborting!\n");
      pause();   
      std::exit(EXIT_FAILURE);
   }

   for (Block const& line : lines)
   {
      // Base64 decode every line
      Block decoded = base64decode(line.data, line.len);
      //PrintToConsole(decoded.data, decoded.len);

      // Insert into vector
      out.push_back( decoded );
   }

   return out;
}

BlockVector getCiphertexts(BlockVector& VPlaintexts, unsigned int* puiMaxSize)
{
   // Create an empty vector
   BlockVector out;

   // Encrypt under CTR mode with fixed-nonce (0x0000000000000000)
   uint64_t ui64Nonce = 0;

   for (Block const& plaintext : VPlaintexts)
   {
      // Encrypt with CTR mode
      Block ciphertext(plaintext.len);
      AES_CTR_Encrypt(plaintext.data, plaintext.len, ciphertext.data, &ciphertext.len, auchServerKey, ui64Nonce);

      // Insert into vector
      out.push_back( ciphertext );

      // Update puiMaxSize
      if ( ciphertext.len > *puiMaxSize )
      {
         *puiMaxSize = ciphertext.len;
      }
   }

   return out;
}

int main()
{
   printf("|- - - - - - - - - - - - - - - - - - - - - - - \n");
   printf("|   Break fixed-nonce CTR mode statistically  |\n");
   printf("|- - - - - - - - - - - - - - - - - - - - - - - \n");

   unsigned int iMaxSize = 0;

   // Get the plaintexts from file
   BlockVector VPlaintexts = getPlaintexts();

   // Get the ciphertexts
   BlockVector VCiphertexts  = getCiphertexts(VPlaintexts, &iMaxSize);

   // A block for the keystream
   Block keystream(iMaxSize);
   keystream.set_to_zeroes();

   // ---------------------------------------------------------------------
   // Approach: try to guess every byte of the keystream
   // For each byte, try all 0xFF values.
   // Then, for each cipherext, get the resulting char and give it a score.
   // The value with the best score if the probable byte of the keystream
   // ---------------------------------------------------------------------

   // Guess every byte of the keystream
   for ( size_t i = 0; i < iMaxSize; i++ )
   {
      int iBestScore = 0;

      // Try all the 0xFF characters
      for (int iKeyByte = 0; iKeyByte < 256; iKeyByte++)
      {
         int iTempScore = 0;

         // Get a score for all ciphertexts
         for (Block const& ciphertext : VCiphertexts)
         {
            if ( ciphertext.len > i )
            {
               char chByte = iKeyByte ^ ciphertext.data[i];

               if ( 0 == i)
               {
                  iTempScore += score_byte(chByte, true);
               }
               else
               {
                  iTempScore += score_byte(chByte, false);
               }
            }
         }

         if (iTempScore > iBestScore)
         {
            iBestScore = iTempScore;
            keystream.data[i] = iKeyByte;
         }
      }
   }

   // ---------------------------------------------------------------------
   // Now that we know the keystream, unravel the plaintexts
   // and compare with the originals
   // ---------------------------------------------------------------------
   for (unsigned i = 0; i < VCiphertexts.size(); i++ )
   {
      Block recovered( VCiphertexts[i].len );
      XOR_encrypt( VCiphertexts[i].data, VCiphertexts[i].len, keystream.data, VCiphertexts[i].len, recovered.data );

      // Print
      if ( 0 == memcmp( VPlaintexts[i].data, recovered.data, recovered.len ) )
      {
         printf( "Exact match:\n" );
      }
      else
      {
         printf( "# # # # # # # # # # # # # # # # # # # #\n" );
         printf( "          Not a match\n" );
         printf( "# # # # # # # # # # # # # # # # # # # #\n" );
      }
      PrintToConsole(VPlaintexts[i].data, VPlaintexts[i].len);
      PrintToConsole(recovered.data, recovered.len);
      printf("\n");
   }

   pause();

   return 0;
}