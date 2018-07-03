#include <stdio.h>
#include <stdlib.h>


// Common for cryptopals
#include "util.h"
#include "crypto_util.h"

// Globals for this challenge
unsigned char auchKey[16] = { 0xAF, 0x89, 0x83, 0x29, 0x08, 0xD7, 0xF8, 0x97, 0x24, 0x89, 0xF7, 0x28, 0x9F, 0x78, 0x9E, 0x15 };


Block profile_for(const char* pchEmail)
{
   static unsigned int uiUID = 1;

   // Create a Block object to be returned.
   Block output;

   // Convert UID into string
   char strUID[5] = { 0 };
   snprintf(strUID, sizeof(strUID), "%03d", uiUID);

   // Check if the email contains forbidden metacharacters ('&' and '=')
   string strValidatedEmail(pchEmail);
   removeCharsFromString(strValidatedEmail, "&=");

   // Fill 
   DictionaryEntry role("role", "user", NULL);
   DictionaryEntry uid("uid", strUID, &role);
   DictionaryEntry email("email", strValidatedEmail.c_str(), &uid);
   
   uiUID++;

   // Format the cookie
   output.alloc(role.getLength() + uid.getLength() + email.getLength() + 5); // 3 * '=' + 2 * '&'
   int iOffset = 0;

   for (DictionaryEntry* entry = &email; entry; entry = entry->nextEntry)
   {
      // Add the key
      memcpy(&output.data[iOffset], entry->key.data, entry->key.len);
      iOffset += entry->key.len;

      // Add a '='
      output.data[iOffset] = '=';
      iOffset++;

      // Add the value
      memcpy(&output.data[iOffset], entry->value.data, entry->value.len);
      iOffset += entry->value.len;

      // Add either a '&' or 0x00
      if (entry->nextEntry)
      {
         // Add a '&'
         output.data[iOffset] = '&';
         iOffset++;
      }
      else
      {
         // We are not adding a 0x00, so output->data should NOT be treated as a C-string
      }
   }

   return output;
}

void parseProfile(unsigned char* uchToBeParsed, unsigned int uiLen)
{
   // A valid profile will have the following pattern: email=foo@bar.com&uid=001&role=user
   string toParse((char*)uchToBeParsed, uiLen);

   // First, split into tokens with '&' as the delimiter
   vector<string> tokens = splitString(toParse, '&');

   if (tokens.size() <= 0)
   {
      return;
   }

   printf("Parsing profile:\n");
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
      }
   }
   catch(...)
   {
      cout << "-->Exception caught while parsing profile<--\n";
   }
}

Block encryptUserProfile(const char* pchEmail)
{
   // Create a profile
   Block plaintext = profile_for(pchEmail);

   // This block will be returned by the function
   Block ciphertext(getPKCS7paddedSize(plaintext.len, AES_BLOCK_SIZE));

   // Encrypt
   AES_ECB_Encrypt(plaintext.data, plaintext.len, ciphertext.data, &ciphertext.len, auchKey, true);

   return ciphertext;
}

void decryptUserProfile(Block* ciphertext)
{
   Block plaintext(ciphertext->len);

   // Decrypt
   AES_ECB_Decrypt(ciphertext->data, ciphertext->len, plaintext.data, &plaintext.len, auchKey, true); 

   // Parse
   parseProfile(plaintext.data, plaintext.len);
}

void createAdminProfile(const char* pchEmail)
{
   // -----------------------------------------------------------------------------------------------------------------
   // Craft a bogus email string that will leave 'admin' + padding in a block alone
   // plaintext will be as follows: email=_________&uid=100&role=user
   // so we need 10 characters of garbage to leave the 'email=' in the first block
   // then we can write 'admin' and pad to a full-block, and we don't care about the rest
   // like "##########admin\0xb\0xb\0xb\0xb\0xb\0xb\0xb\0xb\0xb\0xb\0xb";
   // -----------------------------------------------------------------------------------------------------------------
   const char achAdmin[26] = { 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x61, 0x64, 0x6D, 0x69, 0x6E,
                               0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B };

   Block crafted = encryptUserProfile(achAdmin);

   // We are interested on the second block only
   unsigned char auchCrafted[AES_BLOCK_SIZE] = { 0 };
   memcpy(auchCrafted, &crafted.data[AES_BLOCK_SIZE], AES_BLOCK_SIZE);

   // -----------------------------------------------------------------------------------------------------------------
   // Now, create a plaintext that will leave "role=" exactly at the end of a block
   // The length of 'email=' +  '&uid=100&role=' is 20
   // This means that the email we provide must be 12 mod 16
   // -----------------------------------------------------------------------------------------------------------------
   Block hacked = encryptUserProfile(pchEmail);

   // Now, we change the last block of the ciphertext with the one we crafted
   memcpy(&hacked.data[hacked.len - AES_BLOCK_SIZE], auchCrafted, AES_BLOCK_SIZE);

   // Printf information
   printf("\n--- Creating a fake admin account ---\n" );

   // Finally, decrypt it
   decryptUserProfile(&hacked);
}

int main()
{
   printf("|- - - - - - - - - - - - - - - - \n");
   printf("|        ECB cut & paste        |\n");
   printf("|- - - - - - - - - - - - - - - - \n");
   
   // a) Test: don't allow '&' and '='
   printf("Don't allow emails like \'foo@bar.com&role=admin\'.\n");
   printf("An email of that sort would result in something like:\n-> " );

   Block invalid_chars = profile_for("foo@bar.com&role=admin");
   PrintToConsole(invalid_chars.data, invalid_chars.len, true, false, true);

   // b) Normal case: Encrypt the encoded user profile under the key;
   int i = 1;
   while(i--)
   {
      Block ciphertext = encryptUserProfile("foo@bar.com");

      // Decrypt the encoded user profile and parse it.
      decryptUserProfile(&ciphertext);
   }
   
   // c) Using only the user input to profile_for(), make a role = admin profile.
   // strlen(email) must be 12 mod 16
   createAdminProfile("ab@gmail.com");
   createAdminProfile("ab1234567890abcdef@gmail.com");
   createAdminProfile("not_12_mod_16@gmail.com"); // this one is invalid

   pause();

   return 0;
}