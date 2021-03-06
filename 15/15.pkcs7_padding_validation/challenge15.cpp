#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Common for cryptopals
#include "util.h"
#include "crypto_util.h"


int main()
{
   printf("|- - - - - - - - - - - - - - - - \n");
   printf("|   PKCS#7 Padding Validation   |\n");
   printf("|- - - - - - - - - - - - - - - -\n");

   // Handful of test cases
   unsigned char test_1[16] = { 0x49, 0x43, 0x45, 0x20, 0x49, 0x43, 0x45, 0x20, 0x42, 0x41, 0x42, 0x59, 0x04, 0x04, 0x04, 0x04 };
   unsigned char test_2[16] = { 0x49, 0x43, 0x45, 0x20, 0x49, 0x43, 0x45, 0x20, 0x42, 0x41, 0x42, 0x59, 0x05, 0x05, 0x05, 0x05 };
   unsigned char test_3[16] = { 0x49, 0x43, 0x45, 0x20, 0x49, 0x43, 0x45, 0x20, 0x42, 0x41, 0x42, 0x59, 0x01, 0x02, 0x03, 0x04 };
   unsigned char test_4[16] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66 };
   unsigned char test_5[16] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x00 };
   unsigned char test_6[16] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x01 };

   // Place test cases on a vector for ease of access
   std::vector<unsigned char*> test = { test_1, test_2, test_3, test_4, test_5, test_6 };

   for (unsigned i = 0; i < test.size(); i++)
   {
      try
      {
         printf("Validating test %d, original size = 16 --> ", i+1);
         fflush(stdout);

         unsigned int uiPlaintextSize = removePCKS7padding(test[i], 16, true);

         printf("ok! New size is : %d\n", uiPlaintextSize);
      }
      catch (const char* szException)
      {
         printf("failed! %s\n", szException);
      }
      catch(...)
      {
         printf("failed! unknow exception\n");
      }
   }


   pause();

   return 0;
}