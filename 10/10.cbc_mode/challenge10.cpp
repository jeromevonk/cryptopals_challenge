#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Common for cryptopals
#include "util.h"
#include "crypto_util.h"


int main()
{
   printf("|- - - - - - - - - - - - - - -\n");
   printf("|      Implement CBC Mode    |\n");
   printf("|- - - - - - - - - - - - - - -\n");

   // ----------------------------------------------------------
   // 1 ) Attempt to cipher, without applying padding
   // ----------------------------------------------------------
   {
      Block plaintext(64);
      Block ciphertext(plaintext.len);
      Block key(AES_BLOCK_SIZE);
      Block IV(AES_BLOCK_SIZE);

      // Set plaintext, key, IV
      plaintext.set_to( 0xAA );
      key.set_to( 0xBB );
      IV.set_to( 0xCC );

      // Encrypt
      AES_CBC_Encrypt(plaintext.data, plaintext.len, ciphertext.data, &ciphertext.len, key.data, IV.data, false);

      // Print to console
      printf("\n\n\tCiphertext is:\n");
      PrintToConsole(ciphertext.data, ciphertext.len, false, true);
   }

   
   // ----------------------------------------------------------
   // 2 ) Attempt to decipher WITH and WITHOUT padding removal
   // ----------------------------------------------------------
   {
      // This is the result of 64-byte "DD" padded and ciphered with AES-CBC
      unsigned char auchCiphertext[80] =
      {
         0xE1, 0xBA, 0xEE, 0x71, 0x74, 0xD3, 0xE2, 0xFD, 0x53, 0x9E, 0xB4, 0x26,
         0xDF, 0x17, 0xE4, 0xEF, 0x54, 0x3B, 0xF0, 0x09, 0x69, 0xFA, 0x21, 0x5A,
         0x4F, 0x38, 0x04, 0xA9, 0x56, 0xED, 0x58, 0x54, 0x14, 0xB6, 0x60, 0x91,
         0x06, 0x5C, 0xB4, 0x69, 0x4E, 0x83, 0x9E, 0x2D, 0xB3, 0x95, 0xF9, 0x57,
         0xEF, 0x1C, 0xFE, 0x8B, 0x1E, 0xA3, 0x35, 0x63, 0x3A, 0xE8, 0xAB, 0xDF,
         0x65, 0x6F, 0x5A, 0x7A, 0xBF, 0x48, 0x97, 0x24, 0x57, 0x57, 0x75, 0xDF,
         0xDD, 0x3F, 0xDF, 0xF6, 0xC0, 0x49, 0xC2, 0xA9
      };

      Block ciphertext(sizeof(auchCiphertext));
      Block plaintext(ciphertext.len);
      Block key(AES_BLOCK_SIZE);
      Block IV(AES_BLOCK_SIZE);

      // Set ciphertext, key, IV
      memcpy(ciphertext.data, auchCiphertext, ciphertext.len);
      key.set_to( 0xEE );
      IV.set_to( 0xFF );

      // ----------------------------------------
      // a. Decrypt without removing the padding
      // ----------------------------------------
      AES_CBC_Decrypt(ciphertext.data, ciphertext.len, plaintext.data, &plaintext.len, key.data, IV.data, false);
      printf("\n\n\tPlaintext is:\n");
      PrintToConsole(plaintext.data, plaintext.len, false, true);

      // ----------------------------------------
      // b. Decrypt removing the padding
      // ----------------------------------------
      AES_CBC_Decrypt(ciphertext.data, ciphertext.len, plaintext.data, &plaintext.len, key.data, IV.data, true);
      printf("\n\n\tPlaintext after padding removal is:\n");
      PrintToConsole(plaintext.data, plaintext.len, false, true);
   }

   // ----------------------------------------------------------
   // 3 ) Encrypt something applying padding
   // ----------------------------------------------------------
   {
      unsigned char auchPlaintext[48] = 
      {
         0x55, 0x6D, 0x20, 0x64, 0x6F, 0x69, 0x73, 0x20, 0x74, 0x72, 0x65, 0x73,
         0x20, 0x71, 0x75, 0x61, 0x74, 0x72, 0x6F, 0x20, 0x63, 0x69, 0x6E, 0x63,
         0x6F, 0x20, 0x73, 0x65, 0x69, 0x73, 0x20, 0x73, 0x65, 0x74, 0x65, 0x20,
         0x6F, 0x69, 0x74, 0x6F, 0x20, 0x6E, 0x6F, 0x76, 0x65, 0x64, 0x65, 0x7A
      };

      unsigned char auchKey[AES_BLOCK_SIZE] = { 0x45, 0x73, 0x74, 0x61, 0x20, 0x65, 0x20, 0x61, 0x20, 0x63, 0x68, 0x61, 0x76, 0x65, 0x2E, 0x2E };
      unsigned char auchIV[AES_BLOCK_SIZE]  = { 0x45, 0x73, 0x74, 0x65, 0x20, 0x65, 0x20, 0x6F, 0x20, 0x49, 0x56, 0x2E, 0x2E, 0x21, 0x21, 0x21 };

      Block plaintext(sizeof(auchPlaintext));
      Block ciphertext(getPKCS7paddedSize(plaintext.len, AES_BLOCK_SIZE));
      Block key(AES_BLOCK_SIZE);
      Block IV(AES_BLOCK_SIZE);

      // Set plaintext, key, IV
      memcpy(plaintext.data, auchPlaintext, plaintext.len);
      memcpy(key.data, auchKey, key.len);
      memcpy(IV.data,  auchIV,  IV.len);

      // Encrypt
      AES_CBC_Encrypt(plaintext.data, plaintext.len, ciphertext.data, &ciphertext.len, key.data, IV.data, true);

      // Print to console
      printf("\n\n\tCiphertext is:\n");
      PrintToConsole(ciphertext.data, ciphertext.len, false, true);
   }

   
   // ----------------------------------------------------------
   // 4 ) Decrypt the challenge itself
   // ----------------------------------------------------------
   {
      // Read the input file
      Block base64Text = ReadFile( "10.txt" );
      if ( 0 == base64Text.len )
      {
         printf("Error reading file\n");
         pause();
         return -1;
      }

      // Base64 decode the input 
      Block ciphertext = base64decode(base64Text.data, base64Text.len);
      Block plaintext(ciphertext.len);
      Block key(16);
      Block IV(16);

      // Set key, IV
      key.set_data("YELLOW SUBMARINE", 16);
      IV.set_to_zeroes();

      // Decrypt
      AES_CBC_Decrypt(ciphertext.data, ciphertext.len, plaintext.data, &plaintext.len, key.data, IV.data, true);

      // Print to console
      printf("\n\n\tPlaintext is:\n");
      PrintToConsole(plaintext.data, plaintext.len);
   }

   // ----------------------------------------------------------
   // 4 ) Encrypt a huge file
   // ----------------------------------------------------------
   {
      // Read the input file
      Block base64Text = ReadFile( "10.txt" );
      if ( 0 == base64Text.len )
      {
         printf("Error reading file\n");
         pause();
         return -1;
      }

      // Base64 decode the input 
      Block ciphertext = base64decode(base64Text.data, base64Text.len);
      Block plaintext(ciphertext.len);
      Block key(16);
      Block IV(16);

      // Set key, IV
      key.set_data("YELLOW SUBMARINE", 16);
      IV.set_to_zeroes();

      // Decrypt
      AES_CBC_Decrypt(ciphertext.data, ciphertext.len, plaintext.data, &plaintext.len, key.data, IV.data, true);

      // Print to console
      printf("\n\n\tPlaintext is:\n");
      PrintToConsole(plaintext.data, plaintext.len);
   }

   pause();

   return 0;
}