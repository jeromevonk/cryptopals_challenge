#pragma once
#include <string.h>
#include <ctype.h>
#include <vector>
#include <cstdint>

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

const char* english_score_table = "*0987654321/\"';:?!_-zqxjkvbpygfwmucl\n,. drhsnioate";
const char* english_table_rest  = "0987654321\"';:?!-,. abcdefghijklmnopqrstuvwxyz";

enum OperationMode
{
   ECB_MODE = 0,
   CBC_MODE,
   CTR_MODE
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

      try
      {
         data = new unsigned char[iSize];
         len = iSize;
      }
      catch(std::bad_alloc& e)
      {
         len = 0;
         printf("#### Allocation failed: %s ###\n", e.what() );
      }
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

   void set_to( int iValue)
   {
      memset( data, iValue, len );
   }

   void set_data( const char* achData, unsigned int uiDataLen )
   {
      memcpy( data, achData, uiDataLen );
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

   // Copy constructor
   Block(const Block& other)
   {
      alloc(other.len);
      memcpy(data, other.data, other.len);
   }

   // Copy assignment operator
   // see (https://en.wikipedia.org/wiki/Rule_of_three_(C%2B%2B_programming))
   Block& operator=(const Block& other)
   {
      // copy the data
      alloc(other.len);
      memcpy(data, other.data, other.len);

      return *this;
   }

};

typedef std::vector<Block> BlockVector;

Block randomBlock(unsigned int uiLen)
{
   Block out(uiLen);
   if (!RAND_bytes(out.data, out.len))
   {
      memset(out.data, 0x5A, out.len); // not much to do.. fill with 0x5A
   }

   return out;
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
Block base64encode(unsigned char* achHexBuffer, int iHexSize)
{
   // Create a Block object to be returned.
   // Alloc the maximum size of the encoded data ( iHexSize * 4 /3 )
   Block out(iHexSize*4/3);

   int iEncodedSize = 0;

   char achThree[3] = {0};
   char achFour[4]  = {0};

   if ( NULL == achHexBuffer || iHexSize <= 0 )
   {
      // return empty Block
      return Block();
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
         out.data[iEncodedSize++] = b64table[(unsigned int)achFour[z]];
      }

      iHexSize -= 3;
   }

   if ( iHexSize > 0 )
   {
      for(int j = 0; j < iHexSize; j++)
      {
         achThree[j] = *(achHexBuffer++);
      }

      for(int j = iHexSize; j < 3; j++)
      {
         achThree[j] = 0x00;
      }

      achFour[0] =  (achThree[0] & 0xfc) >> 2;
      achFour[1] = ((achThree[0] & 0x03) << 4) + ((achThree[1] & 0xf0) >> 4);
      achFour[2] = ((achThree[1] & 0x0f) << 2) + ((achThree[2] & 0xc0) >> 6);
      achFour[3] =   achThree[2] & 0x3f;

      for (int j = 0; j < iHexSize+1; j++)
      {
         out.data[iEncodedSize++] = b64table[(unsigned int)achFour[j]];
      }

      for(int j = iHexSize; j < 3; j++)
      {
         out.data[iEncodedSize++] = '=';
      }
   }

   // This is the actual size of the data
   out.len = iEncodedSize;

   return out;
}
Block base64decode(unsigned char* achEncodedBuffer, int iEncodedSize)
{
   char achFour[4]  = {0};
   int iDecodedSize = 0;

   // Create a Block object to be returned.
   // Alloc the maximum size of the encoded data ( iEncodedSize * 3 / 4 )
   Block temp(iEncodedSize*3/4);

   if ( NULL == achEncodedBuffer || iEncodedSize <= 0 )
   {
      // return empty Block
      return Block();
   }

   if ( iEncodedSize%4 != 0 )
   {
      // return empty Block
      return Block();
   }

   while ( iEncodedSize > 0)
   {
      for (int i = 0; i < 4; i++)
      {
         achFour[i] = findIndex(*(achEncodedBuffer++));
      }

      temp.data[iDecodedSize++] = (achFour[0] << 2 ) | (achFour[1] >> 4 );
      if ( achFour[2] < 64)
      {
         temp.data[iDecodedSize++] = (achFour[1] << 4 ) | (achFour[2] >> 2 );
         if ( achFour[3] < 64)
         {
            temp.data[iDecodedSize++] = (achFour[2] << 6 ) | (achFour[3] >> 0 );
         }
      }

      iEncodedSize -= 4;
   }

   // Copy to output block
   Block out(iDecodedSize);
   memcpy(out.data, temp.data, iDecodedSize );

   return out;
}

// -----------------------------------------------------------------------------
// Give a score to a block of plaintext by evaluating english letter frequency
// -----------------------------------------------------------------------------
int score_byte(unsigned char c, bool bFirst = false)
{
   int iByteScore = 0;

   // ---------------------------------------------------------------------
   // If it's the first byte of a sentence, we give 
   // extra point if it's a capital leter
   // If not, we penalize capital letters
   // ---------------------------------------------------------------------
   if ( true == bFirst )
   {
      if ( isupper(c) )
      {
         c = tolower(c);
         iByteScore += 100;
      }
   }
   else
   {
      if ( isupper(c) )
      {
         c = tolower(c);
         iByteScore -= 100;
      }
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
// 
// -----------------------------------------------------------------------------
/*unsigned char englishXORspace[73] = 
{
	0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
	0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
	0x59, 0x5A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
	0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
	0x77, 0x78, 0x79, 0x7A, 0x02, 0x07, 0x1B, 0x1A, 0x1F, 0x01, 0x0C, 0x0E,
	0x00, 0x0D, 0x7F, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
	0x10
};*/

bool XORedAgainsSpace(unsigned char c)
{
   // XOR against space
   c ^= 0x20;

   // If it's a leter, convert to lowercase
   if ( isupper(c) )
   {
      c = tolower(c);
   }

   const char *where = strchr((char*)english_table_rest, c);

   if (where == NULL)
   {
      return false;
   }
   else
   {
      return true;
   }
}



// -----------------------------------------------------------------------------
// MT 19937 - Mersenne Twister Pseudo Random Number Generator
// -----------------------------------------------------------------------------
class MersenneTwister {

public:
   MersenneTwister( unsigned int uiSeed ) 
   {
       uiIndex = N+1;
       auiMT = new unsigned int[N];

       // Seed
       seed( uiSeed );
   }

   ~MersenneTwister()
   {
      delete[] auiMT;
   }
    
   unsigned int extract() 
   {
      // Extract a tempered value based on MT[index] calling twist() every N numbers
      if ( uiIndex >= N )
      {
         if (uiIndex > N )
         {
           //error "Generator was never seeded"
           // Alternatively, seed with constant value; 5489 is used in reference C code[46]
         }
         twist();
      }

      // Temper the value
      unsigned int y = auiMT[uiIndex];
      
      // Temper the value
      y ^= ((y >> 11) & 0xFFFFFFFF);
      y ^= ((y << 7)  & 0x9D2C5680);
      y ^= ((y << 15) & 0xEFC60000);
      y ^=  (y >> 18);
      
      // Increment uiIndex
      uiIndex++;
      
      return 0xFFFFFFFF & y;
   }

private:
   void seed(unsigned int uiSeed) 
   {
      // Initialize the generator from a seed
      uiIndex = N;
      auiMT[0] = uiSeed;
      for (unsigned int i = 1; i < N; i++) 
      {
         auiMT[i] = 0xFFFFFFFF & ( 0x6c078965 * (auiMT[i-1] ^ (auiMT[i-1] >> 30 )) + i );
      }
   }
    
   void twist() 
   {

      for ( unsigned int i = 0; i < N; i++ )
      {
         unsigned int x  = (auiMT[i] & UPPER_MASK) + (auiMT[(i + 1) % N] & LOWER_MASK);
         unsigned int xA = x >> 1;

         // If the lowest bit of x is 1
         if ( x % 2 != 0 )
         {
            xA ^= 0x9908B0DF;
         }

         auiMT[i] = auiMT[(i + 397) % N] ^ xA;
      }

      uiIndex = 0;
   }

   // Create an array with length N to store the state of the generator 
   unsigned int* auiMT;

   // Index
   unsigned int uiIndex;
    
   // constants
   const unsigned int N = 624;    // degree of recurrence
   const unsigned int LOWER_MASK = 0x7FFFFFFF; // ( 1 << 31 ) - 1;
   const unsigned int UPPER_MASK = 0x80000000; //~LOWER_MASK & 0xFFFFFFFF;
};



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
bool validPKCS7padding( unsigned char* auchPlaintext, unsigned int uiLen, unsigned int* puiNewLen)
{
   bool bValid = true;
   *puiNewLen = uiLen;
   unsigned int uiPaddingSize = auchPlaintext[uiLen - 1]; // this is the last byte of the plaintext [0 to uiLen-1]

   // Padding must be smaller than the actual size
   if (uiPaddingSize >= uiLen || uiPaddingSize == 0)
   {
      bValid = false;
   }
   else
   {
      *puiNewLen -= uiPaddingSize;

      // Determine if it has valid PKCS#7 padding
      for (unsigned int i = uiLen - 1; i >= *puiNewLen; i--)
      {
         if (auchPlaintext[i] != uiPaddingSize)
         {
            bValid = false;
            break;
         }
      }
   }
   
   return bValid;
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
   bool bValid = false;
   unsigned int uiNewSize = 0;

   bValid = validPKCS7padding(auchPlaintext, uiLen, &uiNewSize);

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

   try
   {
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

      // Clean up
      delete[] pucWorkingBuffer;
   }
   catch(std::bad_alloc& e)
   {
      *puiCiphertextLen = 0;
      memset( auchCiphertext, 0, uiWorkingSize );
      printf("Allocation failed: %s\n", e.what() );
   }

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

   try
   {
      // Allocate the working buffer
      pucWorkingBuffer = new unsigned char[uiWorkingSize]; //TODO: Test this with a huge value of uiWorkingSize

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

      // Clean up
      delete[] pucWorkingBuffer;
   }
   catch(std::bad_alloc& e)
   {
      *puiCiphertextLen = 0;
      memset( auchCiphertext, 0, uiWorkingSize );
      printf("Allocation failed: %s\n", e.what() );
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

void AES_CTR_Encrypt(unsigned char* auchInput, unsigned int uiInputLen, unsigned char* auchOutput, unsigned int* puiOutputLen, unsigned char* aucKey, uint64_t ui64Nonce)
{
   AES_KEY key;
   AES_set_encrypt_key(aucKey, 8 * AES_BLOCK_SIZE, &key);

   unsigned char ucFirstStage[16]  = {0};
   unsigned char ucMiddleStage[16] = {0};

   // --------------------------------------------------------------------------------
   // CTR MODE
   // First, concat the nonce and the counter, which starts at zero (ucFirstStage).
   // Encrypt it under AES (ucMiddleStage).
   // Finally, XOR against the auchInput to get auchOutput.
   // (see https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR))
   // --------------------------------------------------------------------------------

   // ucFirstStage: first 8 bytes are the nonce
   memcpy( &ucFirstStage[0], &ui64Nonce, sizeof( ui64Nonce ) );

   // ucFirstStage: last 8 bytes are the counter
   // Get a pointer to a 64bit unsigned int and
   // give it the address of the 8th byte of ucFirstStage
   uint64_t* pui64Counter = (uint64_t*)&ucFirstStage[8];
   *pui64Counter = 0;

   // Number of blocks
   int iNumOfBlocks = *puiOutputLen / 16;
   if ( *puiOutputLen % 16 != 0 )
   {
      iNumOfBlocks++;
      //printf( "Size %d, blocks %d\n", *puiOutputLen, iNumOfBlocks );
   }

   for (int i = 0; i < iNumOfBlocks; i++)
   {
      // Block cipher encryption
      AES_ecb_encrypt(ucFirstStage, ucMiddleStage, &key, AES_ENCRYPT);

      // ----------------------------------------------------------------------------
      // Now, XOR the Middle-Stage witht the Input
      // Must pay attention to the fact that, in CTR mode, padding is not mandatory, 
      // so the uiInputLen is probably not  a multiple of AES_BLOCK_SIZE.
      // This means that, for the last block, we don't use all the bytes 
      // of the ucMiddleStage to XOR against auchInput
      // ----------------------------------------------------------------------------
      if ( (int)uiInputLen >= (i+1) * AES_BLOCK_SIZE)
      {
         // This is not the last block or it is a full block
         XOR_encrypt(ucMiddleStage, 16, &auchInput[i * AES_BLOCK_SIZE], 16, &auchOutput[i * AES_BLOCK_SIZE]);
      }
      else
      {
         // This is the last block. How many bytes to copy?
         int iConsideredBytes = uiInputLen - (i * AES_BLOCK_SIZE);
         //printf( "%d bytes remaining\n", iConsideredBytes );
         XOR_encrypt(ucMiddleStage, iConsideredBytes, &auchInput[i * AES_BLOCK_SIZE], iConsideredBytes, &auchOutput[i * AES_BLOCK_SIZE]);
      }

      // Increment counter
      *pui64Counter += 1;
   }
}