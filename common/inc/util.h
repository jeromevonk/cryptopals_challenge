#include "crypto_util.h"

#include <fstream>      // std::ifstream
#include <cstdlib>
#include <algorithm>
#include <sstream>
#include <iterator>
#include <iostream>
#include <new>          // std::bad_alloc
#include <functional> 
#include <cctype>
#include <locale>

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

// --------------------------------------------------------------------------------------
// String trimming
// from: https://stackoverflow.com/questions/216823/whats-the-best-way-to-trim-stdstring
// --------------------------------------------------------------------------------------


// Trim from beggining of string
static inline std::string &ltrim(std::string &s) 
{
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
    return s;
}

// Trim from end of string
static inline std::string &rtrim(std::string &s) 
{
    s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    return s;
}

// Trim from beggining and end of string
static inline std::string &trim(std::string &s) 
{
    return ltrim(rtrim(s));
}

// -----------------------------------------------------------------------
// Read / write the whole file
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

BlockVector GetLinesFromFile( const char* szFile )
{
   // Good reference: [https://gehrcke.de/2011/06/reading-files-in-c-using-ifstream-dealing-correctly-with-badbit-failbit-eofbit-and-perror/]

   // Create an empty vector
   BlockVector out;

   // Create an ifstream
   std::ifstream is(szFile, std::ifstream::binary);
   if (!is)
   { 
      return out;
   }

   // Add every line to the vector
   std::string line;

   while ( std::getline(is, line) ) 
   {
      // Trim
      line = trim( line );

      // Create a block
      Block temp( line.size() );
      temp.set_data( line.c_str(), line.size() );

      // Insert into vector
      out.push_back(temp);
   }

   is.close();

   return out;
}
// -----------------------------------------------------------------------
// Get the next line of the file
// -----------------------------------------------------------------------
/*Block GetNextLine( FILE* fp)
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
}*/

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



