int main(int argc, char *argv[]) {
  for (int i = 0; i < 100; i++) {
    int *i_ptr = &i;
    sample_obf_fib(i_ptr);
  }
}