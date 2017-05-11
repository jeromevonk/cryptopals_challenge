#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Common for cryptopals
#include "util.h"
#include "crypto_util.h"

// Globals for this challenge
unsigned char auchKey[16] = { 0xAF, 0x89, 0x83, 0x29, 0x08, 0xD7, 0xF8, 0x97, 0x24, 0x89, 0xF7, 0x28, 0x9F, 0x78, 0x9E, 0x15 };

void encryptUserData(const char* pchUserData, Block* ciphertext)
{
   char toPrepend[] = "comment1=cooking MCs;userdata=";
   char toAppend[]  = ";comment2= like a pound of bacon";

   // Check if the email contains forbidden metacharacters ('&' and '=')
   string valid_data(pchUserData);
   removeCharsFromString(valid_data, ";=");

   // Prepend/append the bytes
   Block plaintext( strlen(toPrepend) + valid_data.length() + strlen(toAppend) );
   ciphertext->alloc(getPKCS7paddedSize(plaintext.len, AES_BLOCK_SIZE));

   int iOffset = 0;

   memcpy(&plaintext.data[iOffset], toPrepend, strlen(toPrepend));
   iOffset += strlen(toPrepend);

   memcpy(&plaintext.data[iOffset], valid_data.c_str(), valid_data.length());
   iOffset += valid_data.length();

   memcpy(&plaintext.data[iOffset], toAppend, strlen(toAppend));
   iOffset += strlen(toAppend);

   // The IV will be zero
   Block IV(AES_BLOCK_SIZE);
   IV.set_to_zeroes();

   // Encrypt
   AES_CBC_Encrypt(plaintext.data, plaintext.len, ciphertext->data, &ciphertext->len, auchKey, IV.data, true);
}

bool checkForAdminRights(Block* ciphertext)
{
   bool bRet = false;
   Block plaintext(ciphertext->len);

   // The IV will be zero
   Block IV(AES_BLOCK_SIZE);
   IV.set_to_zeroes();

   // Decrypt
   AES_CBC_Decrypt(ciphertext->data, ciphertext->len, plaintext.data, &plaintext.len, auchKey, IV.data, true);

   // A valid profile will have the following pattern: email=foo@bar.com&uid=001&role=user
   string toParse((char*)plaintext.data, plaintext.len);

   // Print information
   cout << "Parsing profile: \'" + toParse + "\'\n";

   // First, split into tokens with ';' as the delimiter
   vector<string> tokens = splitString(toParse, ';');

   if (tokens.size() <= 0)
   {
      return bRet;
   }

   try
   {
      for (unsigned int i = 0; i < tokens.size(); i++)
      {
         // Now, split into key and value, with '=' as the delimiter
         vector<string> item = splitString(tokens.at(i), '=');
         if (item.size() <= 1)
         {
            printf("Invalid entry\n");
            continue;
         }

         cout << item.at(0) << ": \'" << item.at(1) << "\'\n";

         if ( 0 == item.at(0).compare("admin") )
         {
            if ( 0 == item.at(1).compare("true") )
            {
               bRet = true;
            }
         }
      }
   }
   catch (...)
   {
      cout << "-->Exception caught while parsing<--\n";
   }

   if (bRet)
   {
      cout << "Admin rights granted!\n\n";
   }
   else
   {
      cout << "No admin rights\n\n";
   }

   return bRet;
}

int main()
{
   printf("|- - - - - - - - - - - - - - - - \n");
   printf("|    CBC bitflipping attacks     |\n");
   printf("|- - - - - - - - - - - - - - - - \n");

   Block ciphertext;

   // --------------------------------------------------------------------------------
   // It should no be possible to produce a admin profile just by providing the input
   // --------------------------------------------------------------------------------

   // Create an entry
   encryptUserData("JohnDoe;admin=true", &ciphertext);

   // Decrypt an check for admin rights
   checkForAdminRights(&ciphertext);


   // ------------------------------------------------------------------------------------------
   // Modify the ciphertext to get admin rights
   // the plaintext will be like:
   // "comment1=cooking MCs;userdata=This data is bogus:admin<true;comment2= like a pound of bacon";
   // so our bytes of interest are: 48 and 54
   // Knowing that, we mess with the bytes of the previous block: 32 and 38
   // The block containing the bytes we mess with will become rubish, but we consider
   // that it is acceptable, for the challenge, that the userdata is rubbish
   // ------------------------------------------------------------------------------------------

   // Create an entry
   encryptUserData("This data is bogus:admin<true", &ciphertext);

   // Modify the ciphertext
   ciphertext.data[32] ^= 0x01;
   ciphertext.data[38] ^= 0x01;

   // Decrypt an check for admin rights
   checkForAdminRights(&ciphertext);

   pause();

   return 0;
}