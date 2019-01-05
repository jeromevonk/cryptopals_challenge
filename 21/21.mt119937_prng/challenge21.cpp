#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <random>

// Common for cryptopals
#include "util.h"
#include "crypto_util.h"



int main()
{
   printf("|- - - - - - - - - - - - - - - - - - - - - - - \n");
   printf("|           Implement MT 19937 PRNG           |\n");
   printf("|- - - - - - - - - - - - - - - - - - - - - - - \n");

   // Instantiate and seed
   MersenneTwister mt = MersenneTwister(10);

   // We will compare against std library
   std::mt19937 generator(10);

   printf("Random numbers generated:\n");
   printf("Mine: %u, std: %u\n", mt.extract(), generator());
   printf("Mine: %u, std: %u\n", mt.extract(), generator());
   printf("Mine: %u, std: %u\n", mt.extract(), generator());
   printf("Mine: %u, std: %u\n", mt.extract(), generator());
   printf("Mine: %u, std: %u\n", mt.extract(), generator());

   pause();

   return 0;
}