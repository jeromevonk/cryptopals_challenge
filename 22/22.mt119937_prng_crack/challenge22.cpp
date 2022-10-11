#include <stdio.h>
#include <stdlib.h>
#include <chrono>
#include <thread>

// Common for cryptopals
#include "util.h"
#include "crypto_util.h"



int main()
{
   printf("|- - - - - - - - - - - - - - - - - - - - - - - \n");
   printf("|            Crack an MT 19937 seed           |\n");
   printf("|- - - - - - - - - - - - - - - - - - - - - - - \n");

   // Sleeping for rand seconds
   unsigned int uiToSleep = 1;
   printf("Sleeping for %u seconds\n", uiToSleep);
   std::this_thread::sleep_for(std::chrono::seconds(uiToSleep));

   // Current unix timestamp
   unsigned __int64 now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
   printf("Current timestamp is %u\n", now);

   // Instantiate and seed
   MersenneTwister mt = MersenneTwister(now);

   // Sleeping for rand seconds
   uiToSleep = 2;
   printf("Sleeping for %u seconds\n", uiToSleep);
   std::this_thread::sleep_for(std::chrono::seconds(uiToSleep));

   // Extract RNG
   unsigned long ulRandom = mt.extract();
   printf("Extracted RNG: %lu\n", ulRandom);

   pause();

   return 0;
}