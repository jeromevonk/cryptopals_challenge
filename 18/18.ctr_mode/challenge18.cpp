#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Common for cryptopals
#include "util.h"
#include "crypto_util.h"

// Globals for this challenge
unsigned char auchServerKey[16] = { 0xAF, 0x89, 0x83, 0x29, 0x08, 0xD7, 0xF8, 0x97, 0x24, 0x89, 0xF7, 0x28, 0x9F, 0x78, 0x9E, 0x15 };

int main()
{
   printf("|- - - - - - - - - - - - - - - - \n");
   printf("|            CTR MODE           |\n");
   printf("|- - - - - - - - - - - - - - - - \n");

   // ----------------------------------------------------------
   // 1 ) Decipher the challenge
   // ----------------------------------------------------------
   {
      // Base4 decode the given ciphertext
      char* achChallenge = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
      Block ciphertext = base64decode( (unsigned char*)achChallenge, strlen(achChallenge) );
      
      // The key is "YELLOW SUBMARINE"
      Block key(AES_BLOCK_SIZE);
      key.set_data("YELLOW SUBMARINE", strlen( "YELLOW SUBMARINE" ) );

      // The given nonce is 0x0000000000000000
      uint64_t ui64Nonce = 0;

      // Plaintext
      Block plaintext(ciphertext.len);

      // Decrypt: note that for CTR mode the function is the same for encryption/decryption
      AES_CTR_Encrypt(ciphertext.data, ciphertext.len, plaintext.data, &plaintext.len, key.data, ui64Nonce);

      // Print to console
      printf("\n\nPlaintext for the challenge is:\n");
      PrintToConsole(plaintext.data, plaintext.len);
   }

   // ----------------------------------------------------------
   // 2 ) Encrypt a file
   // ----------------------------------------------------------
   {
      // Get file contents
      Block plaintext = ReadFile( "IMPORTANT_FILE.dat" );
      if ( 0 == plaintext.len )
      {
         printf("Error reading file\n");
         pause();
         return -1;
      }
      
      // The key
      Block key(AES_BLOCK_SIZE);
      key.set_data("Banana banana !!", AES_BLOCK_SIZE );

      // The nonce
      uint64_t ui64Nonce = 0x1234567890abcdef;

      // Ciphertext
      Block ciphertext(plaintext.len);

      // Decrypt: note that for CTR mode the function is the same for encryption/decryption
      AES_CTR_Encrypt(plaintext.data, plaintext.len, ciphertext.data, &ciphertext.len, key.data, ui64Nonce);

      // Print to console
      if ( WriteFile("IMPORTANT_FILE_ENC.dat", &ciphertext ) )
      {
         printf("File encrypted: IMPORTANT_FILE_ENC.dat\n");
      }
      else
      {
         printf("Failed writing to file. \n");
      }
      
   }

   // ----------------------------------------------------------
   // 3 ) Decrypt a file
   // ----------------------------------------------------------
   {
      // Get file contents
      Block ciphertext = ReadFile( "IMPORTANT_FILE_ENC.dat" );
      if ( 0 == ciphertext.len )
      {
         printf("Error reading file\n");
         pause();
         return -1;
      }
      
      // The key
      Block key(AES_BLOCK_SIZE);
      key.set_data("Banana banana !!", AES_BLOCK_SIZE );

      // The nonce
      uint64_t ui64Nonce = 0x1234567890abcdef;

      // Plaintext
      Block plaintext(ciphertext.len);

      // Decrypt: note that for CTR mode the function is the same for encryption/decryption
      AES_CTR_Encrypt(ciphertext.data, ciphertext.len, plaintext.data, &plaintext.len, key.data, ui64Nonce);

      // Print to console
      if ( WriteFile("IMPORTANT_FILE_DEC.dat", &plaintext ) )
      {
         printf("File decrypted: IMPORTANT_FILE_DEC.dat\n");
      }
      else
      {
         printf("Failed writing to file. \n");
      }
      
   }

   pause();

   return 0;
}