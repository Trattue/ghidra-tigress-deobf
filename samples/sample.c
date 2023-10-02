#include "tigress.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

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


void xtea(long* v, long* k, long N) {
  unsigned long y = v[0], z = v[1], DELTA=0x9e3779b9;
  if (N > 0) {
    /* coding */
    unsigned long limit = DELTA * N, sum=0;
    while (sum != limit) {
      y += (((z << 4) ^ (z >> 5)) + z) ^ (sum + k[sum & 3]);
      sum += DELTA;
      z += (((y << 4) ^ (y >> 5)) + y) ^ (sum + k[(sum >> 11) & 3]);
    }
  } else {
    /* decoding */
    unsigned long sum = DELTA * (-N);
    while (sum) {
      z -= (((y << 4) ^ (y >> 5)) + y) ^ (sum + k[(sum >> 11) & 3]);
      sum -= DELTA;
      y -= (((z << 4) ^ (z >> 5)) + z) ^ (sum + k[sum & 3]);
    }
  }
  v[0] = y;
  v[1] = z;
}

void interact() {
  int choice;
  while (1) {
    printf("> ");
    scanf("%d", &choice);
    switch (choice) {
      case 1: puts("one"); break;
      case 2: puts("two"); break;
      case 3: puts("three"); break;
      default: puts("bye"); return;
    }
  }
}

int main() {}

