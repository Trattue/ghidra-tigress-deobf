int main(int argc , char **argv , char **_formal_envp )
{
  megaInit();
  _global_argc = argc;
  _global_argv = argv;
  _global_envp = _formal_envp;

  char *new_str = argv[1];
  char **str_ptr = &new_str;
  unsigned int str_len = strlen(new_str);
  unsigned int *str_len_ptr = &str_len;
  unsigned int new_hash = HASH_FUNC_OBF(str_ptr, str_len_ptr);
  printf("%x\n", new_hash);
  return 0;
}
