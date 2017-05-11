#include <fstream>      // std::ifstream
#include "crypto_util.h"
#include <cstdlib>
//#include <string.h>
#include <vector>
#include <algorithm>
#include <sstream>
#include <iterator>
#include <iostream>
#include <new>          // std::bad_alloc

using namespace std;


// -----------------------------------------------------
// OS Cross-compile definitions
// -----------------------------------------------------
#ifdef __linux__
   #define sprintf_s snprintf
#endif

void pause()
{
#ifndef __linux__
   system("pause");
#endif
}

class File {
   FILE* m_fp;
public:
   File(const char* n, const char* a)
   {
      m_fp = fopen(n, a);
      if (m_fp == 0)
      {
         throw errno;
      }
   }
   File(FILE* fp)
   {
      m_fp = fp;
      if (m_fp == 0)
      {
         throw errno;
      }
   }

   ~File()
   { 
      fclose(m_fp);
   }

   operator FILE*()
   {
      return m_fp;
   }
};

struct DictionaryEntry
{
   Block key;
   Block value;

   DictionaryEntry* nextEntry;

   void setKey(const char* pKey)
   {
      key.alloc(strlen(pKey));
      memcpy(key.data, pKey, strlen(pKey));
   }

   void setValue(const char* pValue)
   {
      value.alloc(strlen(pValue));
      memcpy(value.data, pValue, strlen(pValue));
   }

   void setNextEntry(DictionaryEntry* next)
   {
      nextEntry = next;
   }

   unsigned int getLength()
   {
      return key.len + value.len;
   }

   DictionaryEntry(const char* pKey, const char* pValue, DictionaryEntry* next = NULL)
   {
      setKey(pKey);
      setValue(pValue);
      setNextEntry(next);
   }

   ~DictionaryEntry()
   {
      nextEntry = NULL;
   }
};


// -----------------------------------------------------------------------
// Read the whole file
// -----------------------------------------------------------------------
int ReadFile(const char* szFile, char* acFileContents, int iMaxSize)
{
   std::ifstream is (szFile, std::ifstream::binary);
   if (!is) 
   {
      return -1;
   }

   // get length of file:
   is.seekg (0, is.end);
   int iContentLen = (int)is.tellg();
   is.seekg (0, is.beg);
   
   if ( iContentLen <= 0 )
   {
      return 0;
   }
   
   if ( iMaxSize < iContentLen ) 
   {
      return -2;
   }

   char* acTempRead = new char [iContentLen];

   //std::cout << "Reading " << iContentLen << " characters... ";
   is.read (acTempRead, iContentLen);
   is.close();
   
   memcpy(acFileContents, acTempRead, iContentLen);
   delete[] acTempRead;

   return iContentLen;
}

bool BlockReadFile(Block* out, const char* szFile)
{
   std::ifstream is(szFile, std::ifstream::binary);
   if (!is)
   {
      return false;
   }

   // get length of file:
   is.seekg(0, is.end);
   int iContentLen = (int)is.tellg();
   is.seekg(0, is.beg);

   if (iContentLen <= 0)
   {
      return false;
   }

   out->alloc(iContentLen);

   is.read((char*)out->data, iContentLen);
   is.close();

   return true;
}


// -----------------------------------------------------------------------
// Get the next line of the file
// -----------------------------------------------------------------------
int GetLine(unsigned char* acNextLine, int iMaximumSize, FILE* fp )
{
   char achTemp[1024];
   if ( NULL == fgets (achTemp, 1024, fp) )
   {
      return 0;
   }

   int iToCopy = strlen(achTemp);  // this already excludes the terminating null-character

   // Remove linebreaks
   while (achTemp[iToCopy -1] == 0x0D || achTemp[iToCopy -1] == 0x0A)
   {
      iToCopy--;
   }

   // Copy to the caller
   if (iToCopy > iMaximumSize)
   {
      iToCopy = iMaximumSize;
   }

   memcpy(acNextLine, achTemp, iToCopy);

   return iToCopy;
}

// -----------------------------------------------------------------------
// Get the next line of the file
// -----------------------------------------------------------------------
int BlockGetLine( FILE* fp, Block* out )
{
   char achTemp[1024];
   
   if (NULL == fgets(achTemp, 1024, fp))
   {
      return 0;
   }

   int iToCopy = strlen(achTemp);  // this already excludes the terminating null-character

   // Remove linebreaks
   while (achTemp[iToCopy - 1] == 0x0D || achTemp[iToCopy - 1] == 0x0A)
   {
      iToCopy--;
   }

   // Copy to the caller
   out->alloc(iToCopy);

   memcpy(out->data, achTemp, iToCopy);

   return iToCopy;
}

// -----------------------------------------------------------------------
// Convert a ASCII encoded string to hex
// -----------------------------------------------------------------------
int String_to_Hex( unsigned char* aucInputAscii, int iInputLen, int iOutputMax, unsigned char* ucOutput )
{
   // The size
   int iOutLength = iInputLen/2; // ignore CR and LF
   if( iOutLength > iOutputMax )
   {
      iOutLength = iOutputMax;
   }

   for( int i = 0; i < iOutLength; i++ )
   {
      if( aucInputAscii[2*i] >= '0' && aucInputAscii[2*i] <= '9' )
      {
         ucOutput[i] = 16*(aucInputAscii[2*i] - '0');
      }
      else if( aucInputAscii[2*i] >= 'A' && aucInputAscii[2*i] <= 'F' )
      {
         ucOutput[i] = 16*(10 + (aucInputAscii[2*i] - 'A'));
      }
      else if( aucInputAscii[2*i] >= 'a' && aucInputAscii[2*i] <= 'f' )
      {
         ucOutput[i] = 16*(10 + (aucInputAscii[2*i] - 'a'));
      }
      else
      {
         return -1;
      }

      if( aucInputAscii[2*i + 1] >= '0' && aucInputAscii[2*i + 1] <= '9' )
      {
         ucOutput[i] += (aucInputAscii[2*i + 1] - '0');
      }
      else if( aucInputAscii[2*i + 1] >= 'A' && aucInputAscii[2*i + 1] <= 'F' )
      {
         ucOutput[i] += 10 + (aucInputAscii[2*i + 1] - 'A');
      }
      else if( aucInputAscii[2*i + 1] >= 'a' && aucInputAscii[2*i + 1] <= 'f' )
      {
         ucOutput[i] += 10 + (aucInputAscii[2*i + 1] - 'a');
      }
      else
      {
         return -1;
      }
   }

   return iOutLength;
}

// -----------------------------------------------------------------------
// Print to console
// -----------------------------------------------------------------------
void PrintToConsole(unsigned char* aucToPrint, int iLength, bool bChar = true, bool bLinefeedEvery16 = false)
{
   if ( bChar )
   {
      for (int i = 0; i < iLength; i++)
      {
         printf("%c", aucToPrint[i]);
      }
   }
   else
   {
      for (int i = 0; i < iLength; i++)
      {
         printf("%02X ", aucToPrint[i]);

         if (bLinefeedEvery16 && i % 16 == 15)
         {
            printf("\n");
         }
      }
   }

   printf("\n");
}


// -----------------------------------------------------------------------
// Convert the whole string to uppercase
// -----------------------------------------------------------------------
void ToUpper(char* acString)
{
   /*for (int i = 0; acString[i] != NULL; i++)
   {
      acString[i] = toupper( acString[i] );
   }*/
}



// -----------------------------------------------------------------------
// Remove characters from string
// adapted from: https://en.wikipedia.org/wiki/Erase%E2%80%93remove_idiom
// -----------------------------------------------------------------------
void removeCharsFromString(string &str, const string &chars)
{
   

   for (unsigned int i = 0; i < chars.length(); i++)
   {
      str.erase( std::remove(str.begin(), str.end(), chars.at(i) ), str.end());
   }
}


// -----------------------------------------------------------------------
// Split string into tokens
// adapted from: http://stackoverflow.com/a/236803/660711
// -----------------------------------------------------------------------
std::vector<std::string> splitString(const std::string &original, char chDelimiter) 
{
   // Return a vector of subtrings
   std::vector<std::string> subStrings;

   // Convert to a stringstream
   std::stringstream ss;
   ss.str(original);

   // Extracts characters from ss and stores into item
   // until the delimitation character is found
   std::string item;

   while (std::getline(ss, item, chDelimiter))
   {
      if ( !item.empty() )
      {
         subStrings.push_back(item);
      }
   }

   return subStrings;
}

