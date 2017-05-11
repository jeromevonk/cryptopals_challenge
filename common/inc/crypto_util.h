#pragma once
#include <string.h>


// Includes for openssl
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rand.h>


// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------
char b64table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                  "abcdefghijklmnopqrstuvwxyz"
                  "0123456789+/=";

const char* english_score_table = "*0987654321/\"'?!_-zqxjkvbwpygumcfl\n,. dhsirnoate";

enum 
{
   ECB_MODE = 0,
   CBC_MODE
};


// -----------------------------------------------------------------------------
// Custom types
// -----------------------------------------------------------------------------
struct Block
{
   unsigned char* data = NULL;
   unsigned int len;
   
   void alloc(int iSize)
   {
      if (data)
      {
         free();
      }

      data = new unsigned char[iSize];
      len = iSize;
   }
   
   void free()
   {
      len  = 0;
      if ( data )
      {
         delete[] data;
         data = NULL;
      }
   }

   void set_to_zeroes()
   {
      memset(data, 0, len);
   }
   
   Block()
   {
      data = NULL;
      len = 0;
   }

   Block(int iSize)
   {
      alloc(iSize);
   }

   ~Block()
   {
      free();
   }

   Block& operator=(const Block& a)
   {
      // copy the data
      free();
      alloc(a.len);
      memcpy(data, a.data, a.len);

      return *this;
   }

};

bool randomBlock(Block* random, unsigned int uiLen)
{
   random->alloc(uiLen);
   if (!RAND_bytes(random->data, random->len))
   {
      memset(random->data, 0x5A, random->len); // not much to do.. fill with 0x5A
      return false;
   }

   return true;
}


// -----------------------------------------------------------------------------
// Base 64 encode/decode
// -----------------------------------------------------------------------------
int findIndex(char ch)
{
   int i;
   for (i = 0; i < 64; i++)
   {
      if ( ch == b64table[i] )
      {
         break;
      }
   }

   return i;
}
int base64encode(unsigned char* achHexBuffer, int iHexSize, unsigned char* achEncodedBuffer)
{
   int iEncodedSize = 0;
   int j = 0;

   char achThree[3] = {0};
   char achFour[4]  = {0};

   if ( NULL == achHexBuffer || NULL == achEncodedBuffer || iHexSize <= 0 )
   {
      return 0;
   }

   while ( iHexSize > 3)
   {
      achThree[0] = *(achHexBuffer++);
      achThree[1] = *(achHexBuffer++);
      achThree[2] = *(achHexBuffer++);


      achFour[0] =  (achThree[0] & 0xfc) >> 2;
      achFour[1] = ((achThree[0] & 0x03) << 4) + ((achThree[1] & 0xf0) >> 4);
      achFour[2] = ((achThree[1] & 0x0f) << 2) + ((achThree[2] & 0xc0) >> 6);
      achFour[3] =   achThree[2] & 0x3f;

      for (int z = 0; z < 4; z++)
      {
         achEncodedBuffer[iEncodedSize++] = b64table[(unsigned int)achFour[z]];
      }

      iHexSize -= 3;
   }

   if ( iHexSize > 0 )
   {
      for(j = 0; j < iHexSize; j++)
      {
         achThree[j] = *(achHexBuffer++);
      }

      for(j = iHexSize; j < 3; j++)
      {
         achThree[j] = 0x00;
      }

      achFour[0] =  (achThree[0] & 0xfc) >> 2;
      achFour[1] = ((achThree[0] & 0x03) << 4) + ((achThree[1] & 0xf0) >> 4);
      achFour[2] = ((achThree[1] & 0x0f) << 2) + ((achThree[2] & 0xc0) >> 6);
      achFour[3] =   achThree[2] & 0x3f;

      for (j = 0; j < iHexSize+1; j++)
      {
         achEncodedBuffer[iEncodedSize++] = b64table[(unsigned int)achFour[j]];
      }

      for(j = iHexSize; j < 3; j++)
      {
         achEncodedBuffer[iEncodedSize++] = '=';
      }
   }

   return iEncodedSize;
}
int base64decode(unsigned char* achEncodedBuffer, int iEncodedSize, unsigned char* achHexBuffer, int iHexMaxSize)
{

   char achFour[4]  = {0};

   int iHexSize = 0;

   if ( NULL == achHexBuffer || NULL == achEncodedBuffer || iEncodedSize <= 0 )
   {
      return 0;
   }

   if ( iHexMaxSize < iEncodedSize*3/4 )
   {
      return 0;
   }

   if ( iEncodedSize%4 != 0 )
   {
      return 0;
   }

   while ( iEncodedSize > 0)
   {
      for (int i = 0; i < 4; i++)
      {
         achFour[i] = findIndex(*(achEncodedBuffer++));
      }

      achHexBuffer[iHexSize++] = (achFour[0] << 2 ) | (achFour[1] >> 4 );
      if ( achFour[2] < 64)
      {
         achHexBuffer[iHexSize++] = (achFour[1] << 4 ) | (achFour[2] >> 2 );
         if ( achFour[3] < 64)
         {
            achHexBuffer[iHexSize++] = (achFour[2] << 6 ) | (achFour[3] >> 0 );
         }
         else
         {
            iHexSize = iHexSize;
         }
      }
      else
      {
         iHexSize = iHexSize;
      }

      iEncodedSize -= 4;
   }

   return iHexSize;
}


// -----------------------------------------------------------------------------
// Give a score to a block of plaintext by evaluating english letter frequency
// -----------------------------------------------------------------------------
int score_byte(unsigned char c)
{
   int iByteScore = 0;

   if ( isupper(c) )
   {
      c = tolower(c);
      iByteScore -= 100;
   }

   const char *where = strchr(english_score_table, c);

   if (where == NULL)
   {
      iByteScore -= 500;
   }
   else
   {
      if (0x00 != c)
      {
         iByteScore += (where - english_score_table) * 10;
      }
   }

   return iByteScore;
}
int scoreBlock(unsigned char* auchBlock, int iBlockLen)
{
   int iBlockScore = 0;

   for (int i = 0; i < iBlockLen; i++)
   {
      iBlockScore += score_byte(auchBlock[i]);
   }

   return iBlockScore > 0 ? iBlockScore : 0;
}

// -----------------------------------------------------------------------------
// Calculate the hamming distance of two buffers
// -----------------------------------------------------------------------------
int hammingDistance(unsigned char* auchBuffer1, unsigned char* auchBuffer2, int iLen)
{
   int iDistance = 0;

   for (int i = 0; i < iLen; i++)
   {
      // For every byte, we will compare every bit
      for (int j = 0; j < 8; j++)
      {
         if ( ((auchBuffer1[i] >> j ) & 0x01) != ((auchBuffer2[i] >> j ) & 0x01) )
         {
            iDistance++;
         }
      }
   }

   return iDistance;
}

// -----------------------------------------------------------------------------
// XOR a string against a single character
// -----------------------------------------------------------------------------
void XOR_string(unsigned char* ucString, int len, char ch)
{
   for ( int i = 0; i < len; i++ )
   {
      ucString[i] ^= ch;
   }
}


// -----------------------------------------------------------------------------
// Encrypt plaintext using a repeating-key XOR
// -----------------------------------------------------------------------------
void XOR_encrypt(unsigned char* auchPlaintext, int iPlaintextSize, unsigned char* auchKey, int iKeySize, unsigned char* auchCiphertext)
{
   for (int i = 0; i < iPlaintextSize; i++ )
   {
      char chByteToApply = auchKey[i % iKeySize];
      auchCiphertext[i] = auchPlaintext[i] ^ chByteToApply;
   }

   return;
}


// -----------------------------------------------------------------------------
// OpenSSL: 
// -----------------------------------------------------------------------------
bool generateRandomKey(unsigned char* auchKey, unsigned int iKeySize)
{
   if (!RAND_bytes(auchKey, iKeySize))
   {
      return false;
   }

   return true;

}

unsigned int getPKCS7paddedSize(unsigned int uiLen, unsigned int uiPadTo)
{
   unsigned int uiPaddedSize = 0;

   if (uiLen == uiPadTo || 0 == uiLen%uiPadTo)
   {
      return uiLen + uiPadTo;
   }
   else
   {
      if (uiLen < uiPadTo)
      {
         uiPaddedSize = uiPadTo;
      }
      else //if (uiLen > uiPadTo)
      {
         uiPaddedSize = (uiLen / uiPadTo + 1) * uiPadTo;
      }

      return uiPaddedSize;
   }
}
unsigned int applyPKCS7padding(unsigned char* auchPlaintext, unsigned int uiLen, unsigned int uiPadTo)
{
   char chToPad;
   unsigned int uiPaddedSize = 0;

   if (uiLen == uiPadTo || 0 == uiLen%uiPadTo)
   {
      chToPad      = uiPadTo;
      uiPaddedSize = uiLen + uiPadTo;
   }
   else
   {
      if (uiLen < uiPadTo)
      {
         chToPad      = uiPadTo - uiLen;
         uiPaddedSize = uiPadTo;
      }
      else //if (uiLen > uiPadTo)
      {
         chToPad      = uiPadTo - uiLen%uiPadTo;
         uiPaddedSize = (uiLen / uiPadTo + 1) * uiPadTo;
      }
   }

   char chLastByte = uiPaddedSize - 1;

   for (int i = uiLen; i <= chLastByte; i++)
   {
      auchPlaintext[i] = chToPad;
   }

   return uiPaddedSize;
}
unsigned int removePCKS7padding(unsigned char* auchPlaintext, unsigned int uiLen, bool bUseExceptions = false)
{
   bool bValid = true;
   unsigned int uiNewSize = uiLen;
   unsigned int uiPaddingSize = auchPlaintext[uiLen - 1]; // this is the last byte of the plaintext [0 to uiLen-1]

   // Padding must be smaller than the actual size
   if (uiPaddingSize >= uiLen || uiPaddingSize == 0)
   {
      bValid = false;
   }
   else
   {
      uiNewSize -= uiPaddingSize;

      // Determine if it has valid PKCS#7 padding
      for (unsigned int i = uiLen - 1; i >= uiNewSize; i--)
      {
         if (auchPlaintext[i] != uiPaddingSize)
         {
            bValid = false;
            break;
         }
      }
   }

   if (false == bValid)
   {
      if (bUseExceptions)
      {
         throw("Invalid PKCS#7 padding");
      }
      else
      {
         // Return the exact same size
         return uiLen;
      }
   }

   // Just to be sure, fill it with 0xFF
   for (unsigned int i = uiLen - 1; i >= uiNewSize; i--)
   {
      auchPlaintext[i] = 0xFF;
   }
   
   return uiNewSize;
}

void AES_ECB_Encrypt(unsigned char* auchPlaintext, unsigned int uiPlaintextLen, unsigned char* auchCiphertext, unsigned int* puiCiphertextLen, unsigned char* aucKey, bool bApplyPadding = true)
{
   AES_KEY key;
   AES_set_encrypt_key(aucKey, 8 * AES_BLOCK_SIZE, &key);

   unsigned char* pucWorkingBuffer = NULL;
   unsigned int   uiWorkingSize = 0;

   // Padding is optional only if uiPlaintextLen is a multiple of 16
   if ( (false == bApplyPadding) && (uiPlaintextLen % 16 == 0) )
   {
      uiWorkingSize = uiPlaintextLen;
   }
   else
   {
      uiWorkingSize = getPKCS7paddedSize(uiPlaintextLen, 16);
      
      if (uiPlaintextLen % 16 != 0)
      {
         // Plaintext length was not 16, so padding is mandatory
         bApplyPadding = true;
      }
   }

   // Allocate the working buffer
   pucWorkingBuffer = new unsigned char[uiWorkingSize];

   // Copy to working buffer
   memcpy(pucWorkingBuffer, auchPlaintext, uiPlaintextLen);

   if ( bApplyPadding )
   {
      // Apply padding, if needed
      *puiCiphertextLen = applyPKCS7padding(pucWorkingBuffer, uiPlaintextLen, 16);
   }
   else
   {
      // No padding. In this case, ciphertext len equals plaintext len
      *puiCiphertextLen = uiPlaintextLen;
   }

   for (unsigned i = 0; i < *puiCiphertextLen; i += 16)
   {
      AES_ecb_encrypt(&pucWorkingBuffer[i], &auchCiphertext[i], &key, AES_ENCRYPT);
   }

   delete[] pucWorkingBuffer;

}
void AES_ECB_Decrypt(unsigned char* auchCiphertext, unsigned int uiCiphertextLen, unsigned char* auchPlaintext, unsigned int* puiPlaintextLen, unsigned char* aucKey, bool bRemovePadding = true)
{
   AES_KEY key;
   AES_set_decrypt_key(aucKey, 8 * AES_BLOCK_SIZE, &key);

   for (unsigned i = 0; i < uiCiphertextLen; i += 16)
   {
      AES_ecb_encrypt(&auchCiphertext[i], &auchPlaintext[i], &key, AES_DECRYPT);
   }

   if (bRemovePadding)
   {
      // Remove padding
      *puiPlaintextLen = removePCKS7padding(auchPlaintext, uiCiphertextLen);
   }
}
void AES_CBC_Encrypt(unsigned char* auchPlaintext, unsigned int uiPlaintextLen, unsigned char* auchCiphertext, unsigned int* puiCiphertextLen, unsigned char* aucKey, unsigned char* aucIV, bool bApplyPadding = true)
{
   AES_KEY key;
   AES_set_encrypt_key(aucKey, 8 * AES_BLOCK_SIZE, &key);

   unsigned char* pucWorkingBuffer = NULL;
   unsigned int   uiWorkingSize = 0;

   // Padding is optional only if uiPlaintextLen is a multiple of 16
   if ( (false == bApplyPadding) && (uiPlaintextLen % 16 == 0) )
   {
      uiWorkingSize = uiPlaintextLen;
   }
   else
   {
      uiWorkingSize = getPKCS7paddedSize(uiPlaintextLen, 16);
      
      if (uiPlaintextLen % 16 != 0)
      {
         // Plaintext length was not 16, so padding is mandatory
         bApplyPadding = true;
      }
   }

   // Allocate the working buffer
   pucWorkingBuffer = new unsigned char[uiWorkingSize];

   // Copy to working buffer
   memcpy(pucWorkingBuffer, auchPlaintext, uiPlaintextLen);

   if ( bApplyPadding )
   {
      // Apply padding, if needed
      *puiCiphertextLen = applyPKCS7padding(pucWorkingBuffer, uiPlaintextLen, 16);
   }
   else
   {
      // No padding. In this case, ciphertext len equals plaintext len
      *puiCiphertextLen = uiPlaintextLen;
   }

   // First step: first block XORed against IV
   unsigned char auchToEncrypt[16] = { 0 };
   XOR_encrypt(&pucWorkingBuffer[0], 16, aucIV, 16, auchToEncrypt);

   for (unsigned i = 0; i < *puiCiphertextLen; i += 16 )
   {
      AES_ecb_encrypt(auchToEncrypt, &auchCiphertext[i], &key, AES_ENCRYPT);

      if ( i + 16 < *puiCiphertextLen)
      {
         // Find the next IV
         XOR_encrypt(&auchCiphertext[i], 16, &pucWorkingBuffer[i+16], 16, auchToEncrypt);
      }
   }
}
void AES_CBC_Decrypt(unsigned char* auchCiphertext, unsigned int uiCiphertextLen, unsigned char* auchPlaintext, unsigned int* puiPlaintextLen, unsigned char* aucKey, unsigned char* aucIV, bool bRemovePadding = true)
{
   AES_KEY key;
   AES_set_decrypt_key(aucKey, 8 * AES_BLOCK_SIZE, &key);

   unsigned char auchIntermediate[16] = { 0 };

   for (unsigned i = 0; i < uiCiphertextLen; i += 16)
   {
      AES_ecb_encrypt(&auchCiphertext[i], auchIntermediate, &key, AES_DECRYPT);

      if ( 0 == i )
      { 
         XOR_encrypt(aucIV, 16, auchIntermediate, 16, &auchPlaintext[i]);
      }
      else
      {
         XOR_encrypt(&auchCiphertext[i-16], 16, auchIntermediate, 16, &auchPlaintext[i]);
      }
   }

   if (bRemovePadding)
   {
      // Remove padding
      *puiPlaintextLen = removePCKS7padding(auchPlaintext, uiCiphertextLen);
   }
}

int detecECBMode(unsigned char* auchCiphertext, unsigned int uiCiphertextLen, unsigned int uiBlockSize, bool bPrint = false)
{
   int iMode = CBC_MODE;
   int iNumberOfBlocks = uiCiphertextLen / uiBlockSize;

   for (int i = 0; i < iNumberOfBlocks; i++)
   {
      for (int j = i + 1; j < iNumberOfBlocks; j++)
      {
         // Get an AES-sized block
         if (0 == memcmp(&auchCiphertext[i * uiBlockSize], &auchCiphertext[j * uiBlockSize], uiBlockSize))
         {
            iMode = ECB_MODE;

            if (bPrint)
            {
               printf("Found two identical blocks(%d and %d)\n", i, j);
               //PrintToConsole(&auchCiphertext[i * 16], 16, false);
            }
         }
      }
   }

   return iMode;
}
