#include <fstream>      // std::ifstream
#include "crypto_util.h"
#include <cstdlib>
#include <vector>
#include <algorithm>
#include <sstream>
#include <iterator>
#include <iostream>
#include <new>          // std::bad_alloc

using namespace std;

// -----------------------------------------------------
// Definitions
// -----------------------------------------------------
#define MAX_LINE_SIZE 1024

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
   File(const char* filename, const char* mode)
   {
      m_fp = fopen(filename, mode);
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
// Read/ write the whole file
// -----------------------------------------------------------------------
Block ReadFile(const char* szFile)
{
   std::ifstream is(szFile, std::ifstream::binary);
   if (!is)
   {
      // return empty Block
      return Block();
   }

   // get length of file:
   is.seekg(0, is.end);
   int iContentLen = (int)is.tellg();
   is.seekg(0, is.beg);

   if (iContentLen <= 0)
   {
      // return empty Block
      return Block();
   }

   // Create a Block object to be returned.
   Block out(iContentLen);

   is.read((char*)out.data, iContentLen);
   is.close();

   return out;
}

bool WriteFile(const char* szFile, Block* contents)
{
   std::ofstream os(szFile, std::ifstream::binary);
   if (!os)
   {
      return false;
   }

   // Write contents
   os.write((char*)contents->data, contents->len);
   os.close();

   return true;
}


// -----------------------------------------------------------------------
// Get the next line of the file
// -----------------------------------------------------------------------
Block GetNextLine( FILE* fp)
{
   char achTemp[MAX_LINE_SIZE];
   
   if (NULL == fgets(achTemp, MAX_LINE_SIZE, fp))
   {
      // return empty Block
      return Block();
   }

   int iToCopy = strlen(achTemp);  // this already excludes the terminating null-character

   // Remove linebreaks
   while (achTemp[iToCopy - 1] == 0x0D || achTemp[iToCopy - 1] == 0x0A)
   {
      iToCopy--;
   }

   // Create a Block object to be returned.
   Block out(iToCopy);
   memcpy(out.data, achTemp, iToCopy);

   return out;
}

// -----------------------------------------------------------------------
// Convert a ASCII encoded string to hex
// -----------------------------------------------------------------------
Block String_to_Hex( unsigned char* aucInputAscii, int iInputLen )
{
   // Create a Block object to be returned.
   Block out(iInputLen/2);

   for( int i = 0; i < iInputLen/2; i++ )
   {
      if( aucInputAscii[2*i] >= '0' && aucInputAscii[2*i] <= '9' )
      {
         out.data[i] = 16*(aucInputAscii[2*i] - '0');
      }
      else if( aucInputAscii[2*i] >= 'A' && aucInputAscii[2*i] <= 'F' )
      {
         out.data[i] = 16*(10 + (aucInputAscii[2*i] - 'A'));
      }
      else if( aucInputAscii[2*i] >= 'a' && aucInputAscii[2*i] <= 'f' )
      {
         out.data[i] = 16*(10 + (aucInputAscii[2*i] - 'a'));
      }
      else
      {
         return -1;
      }

      if( aucInputAscii[2*i + 1] >= '0' && aucInputAscii[2*i + 1] <= '9' )
      {
         out.data[i] += (aucInputAscii[2*i + 1] - '0');
      }
      else if( aucInputAscii[2*i + 1] >= 'A' && aucInputAscii[2*i + 1] <= 'F' )
      {
         out.data[i] += 10 + (aucInputAscii[2*i + 1] - 'A');
      }
      else if( aucInputAscii[2*i + 1] >= 'a' && aucInputAscii[2*i + 1] <= 'f' )
      {
         out.data[i] += 10 + (aucInputAscii[2*i + 1] - 'a');
      }
      else
      {
         return -1;
      }
   }

   return out;
}

// -----------------------------------------------------------------------
// Print to console
// -----------------------------------------------------------------------
void PrintToConsole(unsigned char* aucToPrint, int iLength, bool bChar = true, bool bLinefeedEvery16 = false, bool bExtraLineFeed = false)
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

   if ( bExtraLineFeed )
   {
      printf("\n");
   }
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

