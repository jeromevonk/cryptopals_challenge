#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Common for cryptopals
#include "util.h"
#include "crypto_util.h"

// Globals for this challenge
unsigned char auchServerKey[16] = { 0xAF, 0x89, 0x83, 0x29, 0x08, 0xD7, 0xF8, 0x97, 0x24, 0x89, 0xF7, 0x28, 0x9F, 0x78, 0x9E, 0x15 };

// https://fattybeagle.com/2017/01/03/cryptopals-challenge-19/
// https://github.com/SomMeri/matasano-cryptopals-solutions/blob/master/src/main/java/org/meri/matasano/Set3.java

BlockVector getPlaintexts( )
{
   // Create an empty vector
   BlockVector out;

   // Read all lines from file
   BlockVector lines = GetLinesFromFile( "19.txt" );
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
   printf("|- - - - - - - - - - - - - - - - \n");
   printf("|   Break fixed-nonce CTR mode  |\n");
   printf("|- - - - - - - - - - - - - - - - \n");

   unsigned int iMaxSize = 0;

   // Get the plaintexts from file
   BlockVector VPlaintexts = getPlaintexts();

   // Get the ciphertexts
   BlockVector VCiphertexts  = getCiphertexts(VPlaintexts, &iMaxSize);

   // A block for the keystream
   Block keystream(iMaxSize);
   keystream.set_to_zeroes();

   // Mark the bytes we discovered;
   Block discovered( iMaxSize );
   discovered.set_to_zeroes();

   // --------------------------------------------------------------------------
   // Approach: 
   // - Get one ciphertext and xor with all others (result is XOR of plaintexts)
   // - If there are a lot of letter in the same position ( space XOR letter
   //   is a letter with a switched case) it's probably a space in the observed
   //   plaintext.
   // - Repeat for all ciphertext, trying to unravel the greatest part of
   //   the key (some positions won't contain spaces)
   // --------------------------------------------------------------------------

   unsigned char* aux = new unsigned char[VCiphertexts.size()];

   // Get each ciphertext
   for (unsigned i = 0; i < VCiphertexts.size(); i++ )
   {
      // Now, get every byte of this cipherext
      for ( unsigned j = 0; j < VCiphertexts[i].len; j++ )
      {
         // Has this byte of the keystream been discovered yet?
         if ( 1 == discovered.data[j] )
         {
            // Skip
            continue;
         }

         bool bIsSpace = true;
         int  iChecked = 0;

         // And XOR against all others
         for ( unsigned k = 0; k < VCiphertexts.size(); k++ )
         {
            if ( i == k )
            {
               // It's the same ciphertext. Skip
               continue;
            }
           
            // Skip if the ciphertext does not have this position (i.e., too short)
            if ( j >= VCiphertexts[k].len )
            {
               // Skip
               continue;
            }

            // XOR the two ciphertexts at this position and evaluate
            // if it looks like a space xored against a valid character
            char chByte = VCiphertexts[i].data[j] ^ VCiphertexts[k].data[j];
            if ( false == XORedAgainsSpace( chByte ) )
            {
               // Already failed
               bIsSpace = false;
               break;
            }
            else
            {
               // Increment the counter of how many ciphertexts were checked
               iChecked++;
            }
         }

         // If variable is still true, than the plaintext probably contains a space
         if ( true == bIsSpace )
         {
            // We will consider that the discovered the key byte if there were
            // at least 3 ciphertexts inspected.
            if ( iChecked > 2 )
            {
               // The keystram byte is the ciphertext XOR space
               keystream.data[j]  = 0x20 ^ VCiphertexts[i].data[j];

               // Mark as byte discovered
               discovered.data[j] = 1;
            }
         }
      }
   }

   // ---------------------------------------------------------------------
   // Unravel the plaintexts
   // ---------------------------------------------------------------------
   for (unsigned i = 0; i < VCiphertexts.size(); i++ )
   {     
      // Unravel byte per byte
      for ( unsigned j = 0; j < VCiphertexts[i].len; j++ )
      {
         if ( 0 == discovered.data[j] )
         {
            // This byte of the key is unknown, so print a dash '-'
            printf( "-" );
         }
         else
         {
            printf( "%c", VCiphertexts[i].data[j] ^ keystream.data[j] );
         }
      }

      printf("\n");
   }

   // ---------------------------------------------------------------------
   // Bytes not discovered
   // ---------------------------------------------------------------------
   printf( "\nKeystream bytes not discovered: " );
   for ( unsigned i = 0; i < discovered.len; i++ )
   {
      if ( 0 == discovered.data[i] )
      {
         printf("%d ", i );
      }
   }
   printf("\n");


   pause();

   return 0;
}