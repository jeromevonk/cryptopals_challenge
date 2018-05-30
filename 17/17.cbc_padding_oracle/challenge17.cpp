#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Common for cryptopals
#include "util.h"
#include "crypto_util.h"

// Globals for this challenge
unsigned char auchServerKey[16] = { 0xAF, 0x89, 0x83, 0x29, 0x08, 0xD7, 0xF8, 0x97, 0x24, 0x89, 0xF7, 0x28, 0x9F, 0x78, 0x9E, 0x15 };

#define NUM_TEST_STRINGS 10

void serverEncrypt(Block* plaintext, Block* ciphertext, Block* IV)
{
   // Allocate the ciphertext
   ciphertext->alloc(getPKCS7paddedSize(plaintext->len, AES_BLOCK_SIZE));

   // The IV will be zero
   IV->alloc(AES_BLOCK_SIZE);
   IV->set_to_zeroes();

   // Encrypt
   AES_CBC_Encrypt(plaintext->data, plaintext->len, ciphertext->data, &ciphertext->len, auchServerKey, IV->data, true);

   return;
}

bool serverCheckPadding(Block* ciphertext, Block* IV)
{
   bool bValidPadding = false;

   // Ciphertext to be recovered
   Block plaintext(ciphertext->len);

   // Perform decryption
   AES_CBC_Decrypt(ciphertext->data, ciphertext->len, plaintext.data, &plaintext.len, auchServerKey, IV->data, false);

   // Length without padding: not useful in this case
   unsigned int uiNewLen = 0;

   // Check if padding is valid
   bValidPadding = validPKCS7padding(plaintext.data, plaintext.len, &uiNewLen);

   return bValidPadding;
}

void attackBlock(Block* ciphertext, Block* IV, unsigned int uiAttackPosition, Block* revealed)
{
   // ------------------------------------------------------------------------------------------------------------------
   // We'll attack one block of the ciphertext at a time: the block has AES_BLOCK_SIZE and starts at uiAttackPosition.
   //
   // We will provide the serverCheckPadding() function with two blocks: C1' and C2
   // C1' will be crafted by us and C2 is a valid ciphertext (the one being attacked).
   //
   // The first goal is to find the intermediate state I2, and then find P2 by: P2 = C1 ^ I2
   // (see images at https://robertheaton.com/2013/07/29/padding-oracle-attack/)
   //
   // The intermediate state is the result of the block cipher decription and it is XOR'red with the previous block
   // of ciphertext (or the IV, in case it's the first block) to result in a block of plaintext.
   //
   // How do we find I2? By messing with the last bytes of C1'. We know that I2 = C1' ^ P2'
   // When we get a valid padding, we assume we know what is P2 (either 0x01, 0x02 0x02, 0x03 0x03 0x03, etc) because we
   // crafted block C1' to reach that purpose.
   // ------------------------------------------------------------------------------------------------------------------

   // Craft a block
   Block crafted( 2 * AES_BLOCK_SIZE );

   // Hold the information we obtain
   Block intermediate( AES_BLOCK_SIZE );

   // A pointer to the block being attacked
   unsigned char* chAttackedBlock = &ciphertext->data[uiAttackPosition];

   // A pointer to the previous block (or IV, in case the first block is being attacked)
   unsigned char* chPreviousBlock = (uiAttackPosition == 0) ? &IV->data[0] : &ciphertext->data[uiAttackPosition-AES_BLOCK_SIZE];

   for (char chByteAttacked = 15; chByteAttacked >= 0; chByteAttacked--)
   {
      //--------------------------------------------------
      // Uncover one byte at a time
      //--------------------------------------------------
      for ( unsigned char ch = 0; ch <= 255; ch++ )
      {
         // Padding byte
         unsigned char chPadding = 16 - chByteAttacked;

         // Bytes from [0 to chByteAttacked] are not considered
         // This is not needed, but setting bytes to zero helps at debugging
         memset( &crafted.data[0],  0, crafted.len );

         // We will try values from [0 to 255] for chByteAttacked position
         crafted.data[chByteAttacked] = ch;

         // From [chByteAttacked to 15] we need to fill in what we already know
         // to craft a block that will generate the desired padding
         // (We already have I2 stored).
         //  C1' =  I2 ^ P2'

         for ( int i = chByteAttacked + 1; i < 16; i++ )
         {
            crafted.data[i] = intermediate.data[i] ^ chPadding;
         }

         // C2 is the valid ciphertext - this block is fixed
         memcpy( &crafted.data[16], chAttackedBlock, AES_BLOCK_SIZE );

         if ( serverCheckPadding( &crafted, IV ) )
         {
            // -------------------------------------------------------------------------------------------
            // !!!Tricky part!!!
            // This is very likely the byte we want, but it's possible that the valid padding we obtained
            // was something like (0x03 0x03 0x03) or (0x02 0x02) instead of (0x01).
            // To verify if that is the case, we simply mess with the next-to-last byte of the block
            // If padding is still valid, we know it was 0x01
            // If it was (0x02 0x02), it will become something like (0xAE, 0x02) which is invalid
            //
            // We only need to check this if the byte being attacked is the last one of the block
            // -------------------------------------------------------------------------------------------
            if ( 15 == chByteAttacked )
            {
               // Change only next-to-last byte (14)
               crafted.data[chByteAttacked-1 ] = 0xAA;

               if ( false == serverCheckPadding( &crafted, IV ) )
               {
                  // If it's not valid padding after messing with the next-to-last byte,
                  // it wasn't a (0x01) padding, so not what we're looking for.
                  continue;
               }
            }

            // ---------------------------------------------------------------
            // Time for the math
            // ---------------------------------------------------------------

            // Find the intermediate byte: I2 = C1' ^ P2'
            unsigned char I2 = ch ^ chPadding;

            // C1 is the byte of the valid previous block
            unsigned char C1 = chPreviousBlock[chByteAttacked];

            // Find the plaintext byte: P2 = C1 ^ I2
            unsigned char P2 = C1 ^ I2;

            // Store information
            intermediate.data[chByteAttacked]  = I2;
            revealed->data[chByteAttacked]     = P2;

            break;
         }

         // Did we reach a dead-end?
         if ( ch == 255 )
         {
            printf( "Could not find a valid padding for byte at position %d\n", uiAttackPosition + chByteAttacked );
            break;
         }
      }
   }

   return;
}

void attack(Block* ciphertext, Block* IV, Block* full_plaintext)
{
   // Save a block of the plaintext
   Block fragment( AES_BLOCK_SIZE );

   // Attack every block
   for ( unsigned int iPos = 0; iPos < ciphertext->len; iPos += AES_BLOCK_SIZE )
   {
      //printf("Attacking block %d - position %d\n", (iPos/16+1), iPos );
      attackBlock( ciphertext, IV, iPos, &fragment );

      // Copy plaintext fragment
      memcpy( &full_plaintext->data[iPos], &fragment.data[0], AES_BLOCK_SIZE );
   }

   // Remove padding
   full_plaintext->len = removePCKS7padding(full_plaintext->data, full_plaintext->len);
}

int main()
{
   printf("|- - - - - - - - - - - - - - - - \n");
   printf("|    The CBC padding oracle     |\n");
   printf("|- - - - - - - - - - - - - - - - \n");

   unsigned char auchTestStrings[NUM_TEST_STRINGS][77] =
   {
      "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
      "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
      "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
      "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
      "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
      "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
      "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
      "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
      "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
      "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
   };

   for (int i = 0; i < NUM_TEST_STRINGS; i++ )
   {
      printf( "\nString %d\n", i );
      unsigned char* pTestString = auchTestStrings[i];

      // Base64 decode the input
      int iMaximumSize = strlen((char*)pTestString) * 3 / 4;
      Block decoded(iMaximumSize);
      decoded.len = base64decode(pTestString, strlen((char*)pTestString), decoded.data, iMaximumSize);

      printf("Plaintext: ");
      PrintToConsole(decoded.data, decoded.len, true, true);

      // First, get the ciphertext and IV
      Block ciphertext;
      Block IV;
      serverEncrypt( &decoded, &ciphertext, &IV );

      // Recover the plaintext only knowing the ciphertext and the IV
      Block recovered( ciphertext.len );
      attack( &ciphertext, &IV, &recovered );

      // Print to console
      printf("Recovered: ");
      PrintToConsole(recovered.data, recovered.len, true, true);

      // Does it match?
      if ( 0 == memcmp( decoded.data, recovered.data, decoded.len ) )
      {
         printf( "Match!\n" );
      }
      else
      {
         printf( "Error breaking ciphertext!\n" );
      }
   }

   pause();

   return 0;
}