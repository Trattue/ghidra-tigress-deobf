#include "tigress.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void xtea(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
  unsigned int i;
  uint32_t v0 = v[0], v1 = v[1], sum = 0, delta = 0x9E3779B9;
  for (i = 0; i < num_rounds; i++) {
    v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    sum += delta;
    v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
  }
  v[0] = v0;
  v[1] = v1;
}

void fib(int n) {
  int a = 0;
  int b = 1;
  int s = 1;

  int i;
  for (i = 1; i < n; i++) {
    s = a + b;
    a = b;
    b = s;
  }

  int ignore = printf("fib(%i)=%i\n", n, s);
}

int main(int argc, char **argv) { fib(1); }
