#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
  char *str = argv[1];
  unsigned int str_len = strlen(str);

  unsigned int hash = HASH_FUNC(str, str_len);

  printf("%x\n", hash);
}
