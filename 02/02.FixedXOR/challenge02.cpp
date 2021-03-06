#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Common for cryptopals
#include "util.h"
#include "crypto_util.h"

unsigned char ucData1[36] = {
	0x31, 0x63, 0x30, 0x31, 0x31, 0x31, 0x30, 0x30, 0x31, 0x66, 0x30, 0x31,
	0x30, 0x31, 0x30, 0x30, 0x30, 0x36, 0x31, 0x61, 0x30, 0x32, 0x34, 0x62,
	0x35, 0x33, 0x35, 0x33, 0x35, 0x30, 0x30, 0x39, 0x31, 0x38, 0x31, 0x63
};

unsigned char ucData2[36] = {
	0x36, 0x38, 0x36, 0x39, 0x37, 0x34, 0x32, 0x30, 0x37, 0x34, 0x36, 0x38,
	0x36, 0x35, 0x32, 0x30, 0x36, 0x32, 0x37, 0x35, 0x36, 0x63, 0x36, 0x63,
	0x32, 0x37, 0x37, 0x33, 0x32, 0x30, 0x36, 0x35, 0x37, 0x39, 0x36, 0x35
};


int main()
{
   printf("|- - - - - - - - - - - - - - - - -\n");
   printf("|    XOR of equal-sized buffers  |\n");
   printf("|- - - - - - - - - - - - - - - - -\n");

   // First, hex encode the bytes
   Block data1 = String_to_Hex(ucData1, sizeof(ucData1) );
   Block data2 = String_to_Hex(ucData2, sizeof(ucData2) );

   // Perform the XOR operation
   Block result(data1.len);
   XOR_encrypt(data1.data, data1.len, data2.data, data2.len, result.data);

   // Print to screen
   printf("XORed string is:\n");
   PrintToConsole(result.data, result.len, false);
   
   pause();
   
   return 0;
}