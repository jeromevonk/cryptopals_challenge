#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Common for cryptopals
#include "util.h"
#include "crypto_util.h"

int main()
{
   printf("|- - - - - - - - - - - - - - -\n");
   printf("|        PKCS#7 Padding      |\n");
   printf("|- - - - - - - - - - - - - - -\n");

   unsigned int uiPaddedSize = 0;

   // -------------------------------------------------------------------
   // Case 1: one block of 16
   // -------------------------------------------------------------------
   Block plaintext(16);
   sprintf_s((char*)plaintext.data, plaintext.len, "Yellow");
   uiPaddedSize = applyPKCS7padding(plaintext.data, (int)strlen("Yellow"), plaintext.len);
   
   PrintToConsole(plaintext.data, plaintext.len, false);
   printf("Padded size = %u\n\n", uiPaddedSize);

   // -------------------------------------------------------------------
   // Case 2: two blocks of 16
   // -------------------------------------------------------------------
   plaintext.alloc(32); // calling alloc on an already allocated Block will throw its contents away and alloc the new size
   sprintf_s((char*)plaintext.data, plaintext.len, "banana nanica contem vitamina");
   uiPaddedSize = applyPKCS7padding(plaintext.data, (int)strlen("banana nanica contem vitamina"), plaintext.len);
   
   PrintToConsole(plaintext.data, plaintext.len, false);
   printf("Padded size = %u\n\n", uiPaddedSize);

   // -------------------------------------------------------------------
   // Case 3: matasano challenge, pad to 20 bytes
   // -------------------------------------------------------------------
   plaintext.alloc(20);
   sprintf_s((char*)plaintext.data, plaintext.len, "YELLOW SUBMARINE");
   uiPaddedSize = applyPKCS7padding(plaintext.data, (int)strlen("YELLOW SUBMARINE"), plaintext.len);
   
   PrintToConsole(plaintext.data, plaintext.len, false);
   printf("Padded size = %u\n\n", uiPaddedSize);

   // -------------------------------------------------------------------
   // Case 4: short plaintext
   // -------------------------------------------------------------------
   plaintext.alloc(32);
   sprintf_s((char*)plaintext.data, plaintext.len, "Yet");
   uiPaddedSize = applyPKCS7padding(plaintext.data, (int)strlen("Yet"), plaintext.len);
   
   PrintToConsole(plaintext.data, plaintext.len, false);
   printf("Padded size = %u\n\n", uiPaddedSize);

   // -------------------------------------------------------------------
   // Case 5: bigger plaintext padded to 16
   // -------------------------------------------------------------------
   plaintext.alloc(32);
   sprintf_s((char*)plaintext.data, plaintext.len, "Look outside the raincoats");
   uiPaddedSize = applyPKCS7padding(plaintext.data, (int)strlen("Look outside the raincoats"), 16);
  
   PrintToConsole(plaintext.data, plaintext.len, false);
   printf("Padded size = %u\n\n", uiPaddedSize);

   // -------------------------------------------------------------------
   // Case 6: bigger plaintext padded to 16
   // -------------------------------------------------------------------
   plaintext.alloc(48);
   sprintf_s((char*)plaintext.data, plaintext.len, "NA NA NA NA NA NA NA NA NA BATMAN");
   uiPaddedSize = applyPKCS7padding(plaintext.data, (int)strlen("NA NA NA NA NA NA NA NA NA BATMAN"), 16);
   
   PrintToConsole(plaintext.data, plaintext.len, false);
   printf("Padded size = %u\n\n", uiPaddedSize);

   // -------------------------------------------------------------------
   // Case 7: block sized 16 padded to 16 (must create another block)
   // -------------------------------------------------------------------
   plaintext.alloc(32);
   sprintf_s((char*)plaintext.data, plaintext.len, "1234567890ABCDEF");
   uiPaddedSize = applyPKCS7padding(plaintext.data, (int)strlen("1234567890ABCDEF"), 16);
   
   PrintToConsole(plaintext.data, plaintext.len, false);
   printf("Padded size = %u\n\n", uiPaddedSize);

   pause();

   return 0;
}