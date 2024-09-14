#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
  char *str = argv[1];
  char **str_ptr = &str;
  unsigned int str_len = strlen(str);
  unsigned int *str_len_ptr = &str_len;

  unsigned int hash = HASH_FUNC_OBF(str_ptr, str_len_ptr);

  printf("%x\n", hash);
}
