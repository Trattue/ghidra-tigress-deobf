/* Generated by CIL v. 1.7.3 */
/* print_CIL_Input is false */

struct _IO_FILE ;
enum _1_RSHash_$op ;
union _1_RSHash_$node ;
struct timeval ;
extern int gettimeofday(struct timeval *tv , void *tz ) ;
extern int pthread_cond_broadcast(int *cond ) ;
char **_global_argv  =    (char **)0;
extern int getpagesize() ;
extern int posix_memalign(void **memptr , unsigned int alignment , unsigned int size ) ;
extern int pthread_join(void *thread , void **value_ptr ) ;
char const   *_1_RSHash_$strings  =    "";
typedef unsigned long size_t;
extern  __attribute__((__nothrow__)) size_t ( __attribute__((__nonnull__(1), __leaf__)) strlen)(char const   *__s )  __attribute__((__pure__)) ;
extern int open(char const   *filename , int oflag  , ...) ;
extern int pthread_barrier_destroy(int *barrier ) ;
extern int pthread_mutex_init(int *mutex , int *attr ) ;
extern int strncmp(char const   *s1 , char const   *s2 , unsigned int maxlen ) ;
extern int printf(char const   * __restrict  __format  , ...) ;
int _global_argc  =    0;
extern int pthread_cond_signal(int *cond ) ;
extern int pthread_barrier_init(int *barrier , int *attr , unsigned int count ) ;
extern int scanf(char const   *format  , ...) ;
extern int raise(int sig ) ;
char **_global_envp  =    (char **)0;
extern int unlink(char const   *filename ) ;
union _1_RSHash_$node {
   char _char ;
   unsigned int _unsigned_int ;
   unsigned char _unsigned_char ;
   long _long ;
   unsigned long _unsigned_long ;
   void *_void_star ;
   unsigned short _unsigned_short ;
   unsigned long long _unsigned_long_long ;
   signed char _signed_char ;
   long long _long_long ;
   int _int ;
   short _short ;
};
extern double difftime(long tv1 , long tv0 ) ;
extern int pthread_barrier_wait(int *barrier ) ;
extern void *memcpy(void *s1 , void const   *s2 , unsigned int size ) ;
extern int pthread_mutex_lock(int *mutex ) ;
extern void *dlsym(void *handle , char *symbol ) ;
extern int gethostname(char *name , unsigned int namelen ) ;
extern unsigned long strtoul(char const   *str , char const   *endptr , int base ) ;
extern void abort() ;
extern int fprintf(struct _IO_FILE *stream , char const   *format  , ...) ;
extern void free(void *ptr ) ;
extern void exit(int status ) ;
int main(int argc , char **argv , char **_formal_envp ) ;
extern void signal(int sig , void *func ) ;
typedef struct _IO_FILE FILE;
extern int close(int filedes ) ;
extern int mprotect(void *addr , unsigned int len , int prot ) ;
extern double strtod(char const   *str , char const   *endptr ) ;
extern double log(double x ) ;
extern double ceil(double x ) ;
unsigned int RSHash(char *str , unsigned int len ) ;
enum _1_RSHash_$op {
    _1_RSHash__constant_int$result_STA_0$value_LIT_0 = 117,
    _1_RSHash__store_unsigned_int$left_STA_0$right_STA_1 = 203,
    _1_RSHash__Lt_unsigned_int_unsigned_int2int$left_STA_0$result_STA_0$right_STA_1 = 28,
    _1_RSHash__formal$result_STA_0$value_LIT_0 = 154,
    _1_RSHash__local$result_STA_0$value_LIT_0 = 12,
    _1_RSHash__Mult_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1 = 178,
    _1_RSHash__convert_int2unsigned_long$left_STA_0$result_STA_0 = 228,
    _1_RSHash__branchIfTrue$expr_STA_0$label_LAB_0 = 3,
    _1_RSHash__PlusA_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1 = 7,
    _1_RSHash__constant_unsigned_int$result_STA_0$value_LIT_0 = 152,
    _1_RSHash__load_void_star$left_STA_0$result_STA_0 = 164,
    _1_RSHash__convert_char2unsigned_int$left_STA_0$result_STA_0 = 16,
    _1_RSHash__PlusPI_void_star_unsigned_long2void_star$left_STA_0$result_STA_0$right_STA_1 = 96,
    _1_RSHash__constant_unsigned_long$result_STA_0$value_LIT_0 = 173,
    _1_RSHash__return_unsigned_int$expr_STA_0 = 202,
    _1_RSHash__load_unsigned_int$left_STA_0$result_STA_0 = 249,
    _1_RSHash__goto$label_LAB_0 = 233,
    _1_RSHash__load_char$left_STA_0$result_STA_0 = 204,
    _1_RSHash__Mult_unsigned_long_unsigned_long2unsigned_long$left_STA_0$result_STA_0$right_STA_1 = 105,
    _1_RSHash__store_void_star$right_STA_0$left_STA_1 = 155
} ;
extern int fcntl(int filedes , int cmd  , ...) ;
extern int fclose(void *stream ) ;
extern void perror(char const   *str ) ;
extern int pthread_cond_wait(int *cond , int *mutex ) ;
extern int write(int filedes , void *buf , unsigned int nbyte ) ;
extern int pthread_cond_init(int *cond , int *attr ) ;
extern int ptrace(int request , void *pid , void *addr , int data ) ;
extern unsigned int strnlen(char const   *s , unsigned int maxlen ) ;
extern float strtof(char const   *str , char const   *endptr ) ;
struct timeval {
   long tv_sec ;
   long tv_usec ;
};
extern void qsort(void *base , unsigned int nel , unsigned int width , int (*compar)(void *a ,
                                                                                     void *b ) ) ;
extern long clock(void) ;
extern long time(long *tloc ) ;
extern int rand() ;
extern int read(int filedes , void *buf , unsigned int nbyte ) ;
unsigned char _1_RSHash_$array[1][199]  = { {        _1_RSHash__constant_unsigned_int$result_STA_0$value_LIT_0,        (unsigned char)183,        (unsigned char)198,        (unsigned char)5, 
            (unsigned char)0,        _1_RSHash__local$result_STA_0$value_LIT_0,        (unsigned char)12,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_RSHash__store_unsigned_int$left_STA_0$right_STA_1,        _1_RSHash__constant_unsigned_int$result_STA_0$value_LIT_0, 
            (unsigned char)201,        (unsigned char)248,        (unsigned char)0,        (unsigned char)0, 
            _1_RSHash__local$result_STA_0$value_LIT_0,        (unsigned char)16,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_RSHash__store_unsigned_int$left_STA_0$right_STA_1,        _1_RSHash__constant_unsigned_int$result_STA_0$value_LIT_0,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_RSHash__local$result_STA_0$value_LIT_0, 
            (unsigned char)20,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            _1_RSHash__store_unsigned_int$left_STA_0$right_STA_1,        _1_RSHash__constant_unsigned_int$result_STA_0$value_LIT_0,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_RSHash__local$result_STA_0$value_LIT_0,        (unsigned char)24, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_RSHash__store_unsigned_int$left_STA_0$right_STA_1, 
            _1_RSHash__constant_unsigned_int$result_STA_0$value_LIT_0,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_RSHash__local$result_STA_0$value_LIT_0,        (unsigned char)24,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_RSHash__store_unsigned_int$left_STA_0$right_STA_1,        _1_RSHash__goto$label_LAB_0, 
            (unsigned char)4,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            _1_RSHash__formal$result_STA_0$value_LIT_0,        (unsigned char)1,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_RSHash__load_unsigned_int$left_STA_0$result_STA_0,        _1_RSHash__local$result_STA_0$value_LIT_0,        (unsigned char)24, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_RSHash__load_unsigned_int$left_STA_0$result_STA_0, 
            _1_RSHash__Lt_unsigned_int_unsigned_int2int$left_STA_0$result_STA_0$right_STA_1,        _1_RSHash__branchIfTrue$expr_STA_0$label_LAB_0,        (unsigned char)14,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_RSHash__goto$label_LAB_0,        (unsigned char)4, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_RSHash__goto$label_LAB_0, 
            (unsigned char)108,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            _1_RSHash__local$result_STA_0$value_LIT_0,        (unsigned char)20,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_RSHash__load_unsigned_int$left_STA_0$result_STA_0,        _1_RSHash__local$result_STA_0$value_LIT_0,        (unsigned char)16, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_RSHash__load_unsigned_int$left_STA_0$result_STA_0, 
            _1_RSHash__Mult_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1,        _1_RSHash__formal$result_STA_0$value_LIT_0,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_RSHash__load_void_star$left_STA_0$result_STA_0,        _1_RSHash__load_char$left_STA_0$result_STA_0, 
            _1_RSHash__convert_char2unsigned_int$left_STA_0$result_STA_0,        _1_RSHash__PlusA_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1,        _1_RSHash__local$result_STA_0$value_LIT_0,        (unsigned char)20, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_RSHash__store_unsigned_int$left_STA_0$right_STA_1, 
            _1_RSHash__local$result_STA_0$value_LIT_0,        (unsigned char)16,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_RSHash__load_unsigned_int$left_STA_0$result_STA_0,        _1_RSHash__local$result_STA_0$value_LIT_0,        (unsigned char)12, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_RSHash__load_unsigned_int$left_STA_0$result_STA_0, 
            _1_RSHash__Mult_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1,        _1_RSHash__local$result_STA_0$value_LIT_0,        (unsigned char)16,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_RSHash__store_unsigned_int$left_STA_0$right_STA_1,        _1_RSHash__formal$result_STA_0$value_LIT_0, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            _1_RSHash__constant_unsigned_long$result_STA_0$value_LIT_0,        (unsigned char)1,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_RSHash__constant_int$result_STA_0$value_LIT_0,        (unsigned char)1,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_RSHash__convert_int2unsigned_long$left_STA_0$result_STA_0,        _1_RSHash__Mult_unsigned_long_unsigned_long2unsigned_long$left_STA_0$result_STA_0$right_STA_1, 
            _1_RSHash__formal$result_STA_0$value_LIT_0,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_RSHash__load_void_star$left_STA_0$result_STA_0,        _1_RSHash__PlusPI_void_star_unsigned_long2void_star$left_STA_0$result_STA_0$right_STA_1,        _1_RSHash__store_void_star$right_STA_0$left_STA_1, 
            _1_RSHash__local$result_STA_0$value_LIT_0,        (unsigned char)24,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_RSHash__load_unsigned_int$left_STA_0$result_STA_0,        _1_RSHash__constant_unsigned_int$result_STA_0$value_LIT_0,        (unsigned char)1, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_RSHash__PlusA_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1, 
            _1_RSHash__local$result_STA_0$value_LIT_0,        (unsigned char)24,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_RSHash__store_unsigned_int$left_STA_0$right_STA_1,        _1_RSHash__goto$label_LAB_0,        (unsigned char)133, 
            (unsigned char)255,        (unsigned char)255,        (unsigned char)255,        _1_RSHash__goto$label_LAB_0, 
            (unsigned char)128,        (unsigned char)255,        (unsigned char)255,        (unsigned char)255, 
            _1_RSHash__local$result_STA_0$value_LIT_0,        (unsigned char)20,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_RSHash__load_unsigned_int$left_STA_0$result_STA_0,        _1_RSHash__return_unsigned_int$expr_STA_0}};
extern int strcmp(char const   *a ,
                  char const   *b ) ;
extern void *fopen(char const   *filename , char const   *mode ) ;
extern double sqrt(double x ) ;
extern void *malloc(unsigned int size ) ;
extern long strtol(char const   *str , char const   *endptr , int base ) ;
extern int snprintf(char *str , unsigned int size , char const   *format  , ...) ;
extern int nanosleep(int *rqtp , int *rmtp ) ;
extern int pthread_mutex_unlock(int *mutex ) ;
extern int atoi(char const   *s ) ;
extern int pthread_create(void *thread , void *attr , void *start_routine , void *arg ) ;
extern int fseek(struct _IO_FILE *stream , long offs , int whence ) ;
extern int fscanf(struct _IO_FILE *stream , char const   *format  , ...) ;
void megaInit(void) ;
void megaInit(void) 
{ 


  {

}
}
int main(int argc , char **argv , char **_formal_envp ) 
{ 
  unsigned char *str ;
  unsigned int hash ;
  size_t tmp ;
  unsigned int tmp___0 ;
  int _BARRIER_0 ;

  {
  megaInit();
  _global_argc = argc;
  _global_argv = argv;
  _global_envp = _formal_envp;
  _BARRIER_0 = 1;
  str = (unsigned char *)*(argv + 1);
  tmp = strlen((char const   *)str);
  tmp___0 = RSHash((char *)str, (unsigned int )tmp);
  hash = tmp___0;
  if (hash == 1294241610U) {
    printf((char const   */* __restrict  */)"You win!\n");
  }
  return (0);
}
}
unsigned int RSHash(char *str , unsigned int len ) 
{ 
  char _1_RSHash_$locals[28] ;
  union _1_RSHash_$node _1_RSHash_$stack[1][32] ;
  union _1_RSHash_$node *_1_RSHash_$sp[1] ;
  unsigned char *_1_RSHash_$pc[1] ;
  unsigned char _1_RSHash_$currentOp ;

  {
  _1_RSHash_$sp[0] = _1_RSHash_$stack[0];
  _1_RSHash_$pc[0] = _1_RSHash_$array[0];
  while (1) {
    _1_RSHash_$currentOp = *(_1_RSHash_$pc[0]);
    if (_1_RSHash_$currentOp == _1_RSHash__constant_unsigned_int$result_STA_0$value_LIT_0) {
      (_1_RSHash_$pc[0]) ++;
      (_1_RSHash_$sp[0] + 1)->_unsigned_int = *((unsigned int *)_1_RSHash_$pc[0]);
      (_1_RSHash_$sp[0]) ++;
      _1_RSHash_$pc[0] += 4;
    } else
    if (_1_RSHash_$currentOp == _1_RSHash__Mult_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1) {
      (_1_RSHash_$pc[0]) ++;
      (_1_RSHash_$sp[0] + -1)->_unsigned_int = (_1_RSHash_$sp[0] + -1)->_unsigned_int * (_1_RSHash_$sp[0] + 0)->_unsigned_int;
      (_1_RSHash_$sp[0]) --;
    } else
    if (_1_RSHash_$currentOp == _1_RSHash__PlusPI_void_star_unsigned_long2void_star$left_STA_0$result_STA_0$right_STA_1) {
      (_1_RSHash_$pc[0]) ++;
      (_1_RSHash_$sp[0] + -1)->_void_star = (_1_RSHash_$sp[0] + 0)->_void_star + (_1_RSHash_$sp[0] + -1)->_unsigned_long;
      (_1_RSHash_$sp[0]) --;
    } else
    if (_1_RSHash_$currentOp == _1_RSHash__load_char$left_STA_0$result_STA_0) {
      (_1_RSHash_$pc[0]) ++;
      (_1_RSHash_$sp[0] + 0)->_char = *((char *)(_1_RSHash_$sp[0] + 0)->_void_star);
    } else
    if (_1_RSHash_$currentOp == _1_RSHash__goto$label_LAB_0) {
      (_1_RSHash_$pc[0]) ++;
      _1_RSHash_$pc[0] += *((int *)_1_RSHash_$pc[0]);
    } else
    if (_1_RSHash_$currentOp == _1_RSHash__formal$result_STA_0$value_LIT_0) {
      (_1_RSHash_$pc[0]) ++;
      switch (*((int *)_1_RSHash_$pc[0])) {
      case 1: 
      (_1_RSHash_$sp[0] + 1)->_void_star = (void *)(& len);
      break;
      case 0: 
      (_1_RSHash_$sp[0] + 1)->_void_star = (void *)(& str);
      break;
      }
      (_1_RSHash_$sp[0]) ++;
      _1_RSHash_$pc[0] += 4;
    } else
    if (_1_RSHash_$currentOp == _1_RSHash__constant_int$result_STA_0$value_LIT_0) {
      (_1_RSHash_$pc[0]) ++;
      (_1_RSHash_$sp[0] + 1)->_int = *((int *)_1_RSHash_$pc[0]);
      (_1_RSHash_$sp[0]) ++;
      _1_RSHash_$pc[0] += 4;
    } else
    if (_1_RSHash_$currentOp == _1_RSHash__Mult_unsigned_long_unsigned_long2unsigned_long$left_STA_0$result_STA_0$right_STA_1) {
      (_1_RSHash_$pc[0]) ++;
      (_1_RSHash_$sp[0] + -1)->_unsigned_long = (_1_RSHash_$sp[0] + 0)->_unsigned_long * (_1_RSHash_$sp[0] + -1)->_unsigned_long;
      (_1_RSHash_$sp[0]) --;
    } else
    if (_1_RSHash_$currentOp == _1_RSHash__store_unsigned_int$left_STA_0$right_STA_1) {
      (_1_RSHash_$pc[0]) ++;
      *((unsigned int *)(_1_RSHash_$sp[0] + 0)->_void_star) = (_1_RSHash_$sp[0] + -1)->_unsigned_int;
      _1_RSHash_$sp[0] += -2;
    } else
    if (_1_RSHash_$currentOp == _1_RSHash__local$result_STA_0$value_LIT_0) {
      (_1_RSHash_$pc[0]) ++;
      (_1_RSHash_$sp[0] + 1)->_void_star = (void *)(_1_RSHash_$locals + *((int *)_1_RSHash_$pc[0]));
      (_1_RSHash_$sp[0]) ++;
      _1_RSHash_$pc[0] += 4;
    } else
    if (_1_RSHash_$currentOp == _1_RSHash__store_void_star$right_STA_0$left_STA_1) {
      (_1_RSHash_$pc[0]) ++;
      *((void **)(_1_RSHash_$sp[0] + -1)->_void_star) = (_1_RSHash_$sp[0] + 0)->_void_star;
      _1_RSHash_$sp[0] += -2;
    } else
    if (_1_RSHash_$currentOp == _1_RSHash__load_void_star$left_STA_0$result_STA_0) {
      (_1_RSHash_$pc[0]) ++;
      (_1_RSHash_$sp[0] + 0)->_void_star = *((void **)(_1_RSHash_$sp[0] + 0)->_void_star);
    } else
    if (_1_RSHash_$currentOp == _1_RSHash__constant_unsigned_long$result_STA_0$value_LIT_0) {
      (_1_RSHash_$pc[0]) ++;
      (_1_RSHash_$sp[0] + 1)->_unsigned_long = *((unsigned long *)_1_RSHash_$pc[0]);
      (_1_RSHash_$sp[0]) ++;
      _1_RSHash_$pc[0] += 8;
    } else
    if (_1_RSHash_$currentOp == _1_RSHash__branchIfTrue$expr_STA_0$label_LAB_0) {
      (_1_RSHash_$pc[0]) ++;
      if ((_1_RSHash_$sp[0] + 0)->_int) {
        _1_RSHash_$pc[0] += *((int *)_1_RSHash_$pc[0]);
      } else {
        _1_RSHash_$pc[0] += 4;
      }
      (_1_RSHash_$sp[0]) --;
    } else
    if (_1_RSHash_$currentOp == _1_RSHash__convert_int2unsigned_long$left_STA_0$result_STA_0) {
      (_1_RSHash_$pc[0]) ++;
      (_1_RSHash_$sp[0] + 0)->_unsigned_long = (unsigned long )(_1_RSHash_$sp[0] + 0)->_int;
    } else
    if (_1_RSHash_$currentOp == _1_RSHash__return_unsigned_int$expr_STA_0) {
      (_1_RSHash_$pc[0]) ++;
      return ((_1_RSHash_$sp[0] + 0)->_unsigned_int);
    } else
    if (_1_RSHash_$currentOp == _1_RSHash__Lt_unsigned_int_unsigned_int2int$left_STA_0$result_STA_0$right_STA_1) {
      (_1_RSHash_$pc[0]) ++;
      (_1_RSHash_$sp[0] + -1)->_int = (_1_RSHash_$sp[0] + 0)->_unsigned_int < (_1_RSHash_$sp[0] + -1)->_unsigned_int;
      (_1_RSHash_$sp[0]) --;
    } else
    if (_1_RSHash_$currentOp == _1_RSHash__PlusA_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1) {
      (_1_RSHash_$pc[0]) ++;
      (_1_RSHash_$sp[0] + -1)->_unsigned_int = (_1_RSHash_$sp[0] + -1)->_unsigned_int + (_1_RSHash_$sp[0] + 0)->_unsigned_int;
      (_1_RSHash_$sp[0]) --;
    } else
    if (_1_RSHash_$currentOp == _1_RSHash__convert_char2unsigned_int$left_STA_0$result_STA_0) {
      (_1_RSHash_$pc[0]) ++;
      (_1_RSHash_$sp[0] + 0)->_unsigned_int = (unsigned int )(_1_RSHash_$sp[0] + 0)->_char;
    } else
    if (_1_RSHash_$currentOp == _1_RSHash__load_unsigned_int$left_STA_0$result_STA_0) {
      (_1_RSHash_$pc[0]) ++;
      (_1_RSHash_$sp[0] + 0)->_unsigned_int = *((unsigned int *)(_1_RSHash_$sp[0] + 0)->_void_star);
    } else {

    }
  }
}
}