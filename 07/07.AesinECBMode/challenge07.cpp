#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Common for cryptopals
#include "util.h"
#include "crypto_util.h"

unsigned char auchKey[16] =  { 0x59, 0x45, 0x4C, 0x4C, 0x4F, 0x57, 0x20, 0x53, 0x55, 0x42, 0x4D, 0x41, 0x52, 0x49, 0x4E, 0x45 };

int main()
{
   printf("|- - - - - - - - - - - - - - -\n");
   printf("|        AES in ECB Mode     |\n");
   printf("|- - - - - - - - - - - - - - -\n");

   // ------------------------------------------------------------------------------
   // Read the input file
   // ------------------------------------------------------------------------------
   Block base64Text = ReadFile( "07.txt" );
   if ( 0 == base64Text.len )
   {
      printf("Error reading file\n");
      pause();
      return -1;
   }

   // Base64 decode the input 
   Block ciphertext = base64decode(base64Text.data, base64Text.len);
  
   // Alloc the plaintext
   Block plaintext(ciphertext.len);

   //---[ Decrypt ]----------------------------------------------------------------------
   AES_ECB_Decrypt(ciphertext.data, ciphertext.len, plaintext.data, &plaintext.len, auchKey, true);

   // Print to console
   printf("\n\n\tThe message is:\n");
   PrintToConsole(plaintext.data, plaintext.len);

   pause();

   return 0;
}