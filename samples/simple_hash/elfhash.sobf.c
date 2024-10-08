/* Generated by CIL v. 1.7.3 */
/* print_CIL_Input is false */

union _1_ELFHash_$node ;
struct _IO_FILE ;
enum _1_ELFHash_$op ;
struct timeval ;
extern int gettimeofday(struct timeval *tv , void *tz ) ;
unsigned int ELFHash(char *str , unsigned int len ) ;
extern int pthread_cond_broadcast(int *cond ) ;
char **_global_argv  =    (char **)0;
extern int getpagesize() ;
extern int posix_memalign(void **memptr , unsigned int alignment , unsigned int size ) ;
extern int pthread_join(void *thread , void **value_ptr ) ;
typedef unsigned long size_t;
extern  __attribute__((__nothrow__)) size_t ( __attribute__((__nonnull__(1), __leaf__)) strlen)(char const   *__s )  __attribute__((__pure__)) ;
extern int open(char const   *filename , int oflag  , ...) ;
extern int pthread_barrier_destroy(int *barrier ) ;
extern int strncmp(char const   *s1 , char const   *s2 , unsigned int maxlen ) ;
extern int pthread_mutex_init(int *mutex , int *attr ) ;
char const   *_1_ELFHash_$strings  =    "";
extern int printf(char const   * __restrict  __format  , ...) ;
int _global_argc  =    0;
extern int pthread_cond_signal(int *cond ) ;
extern int pthread_barrier_init(int *barrier , int *attr , unsigned int count ) ;
extern int scanf(char const   *format  , ...) ;
extern int raise(int sig ) ;
char **_global_envp  =    (char **)0;
extern int unlink(char const   *filename ) ;
extern int pthread_barrier_wait(int *barrier ) ;
extern double difftime(long tv1 , long tv0 ) ;
extern int pthread_mutex_lock(int *mutex ) ;
extern void *memcpy(void *s1 , void const   *s2 , unsigned int size ) ;
extern void *dlsym(void *handle , char *symbol ) ;
extern int gethostname(char *name , unsigned int namelen ) ;
extern void abort() ;
extern unsigned long strtoul(char const   *str , char const   *endptr , int base ) ;
extern int fprintf(struct _IO_FILE *stream , char const   *format  , ...) ;
extern void free(void *ptr ) ;
extern void exit(int status ) ;
int main(int argc , char **argv , char **_formal_envp ) ;
extern void signal(int sig , void *func ) ;
typedef struct _IO_FILE FILE;
extern int mprotect(void *addr , unsigned int len , int prot ) ;
extern int close(int filedes ) ;
extern double strtod(char const   *str , char const   *endptr ) ;
extern double log(double x ) ;
union _1_ELFHash_$node {
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
extern double ceil(double x ) ;
enum _1_ELFHash_$op {
    _1_ELFHash__constant_int$result_STA_0$value_LIT_0__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__Shiftlt_unsigned_int_int2unsigned_int$left_STA_0$result_STA_0$right_STA_1 = 104,
    _1_ELFHash__store_unsigned_int$left_STA_0$right_STA_1__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__convert_unsigned_int2long$left_STA_0$result_STA_0__constant_long$result_STA_0$value_LIT_0 = 124,
    _1_ELFHash__return_unsigned_int$expr_STA_0 = 202,
    _1_ELFHash__goto$label_LAB_0 = 233,
    _1_ELFHash__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__constant_int$result_STA_0$value_LIT_0 = 127,
    _1_ELFHash__formal$result_STA_0$value_LIT_0 = 154,
    _1_ELFHash__Shiftrt_unsigned_int_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1__BXor_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1__local$result_STA_0$value_LIT_0__store_unsigned_int$left_STA_0$right_STA_1 = 156,
    _1_ELFHash__constant_unsigned_long$result_STA_0$value_LIT_0__constant_int$result_STA_0$value_LIT_0__convert_int2unsigned_long$left_STA_0$result_STA_0__Mult_unsigned_long_unsigned_long2unsigned_long$left_STA_0$result_STA_0$right_STA_1 = 120,
    _1_ELFHash__store_unsigned_int$left_STA_0$right_STA_1 = 203,
    _1_ELFHash__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0 = 146,
    _1_ELFHash__load_void_star$left_STA_0$result_STA_0__load_char$left_STA_0$result_STA_0__convert_char2unsigned_int$left_STA_0$result_STA_0__PlusA_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1__local$result_STA_0$value_LIT_0 = 218,
    _1_ELFHash__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__constant_unsigned_int$result_STA_0$value_LIT_0__PlusA_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1__local$result_STA_0$value_LIT_0 = 193,
    _1_ELFHash__constant_unsigned_int$result_STA_0$value_LIT_0__local$result_STA_0$value_LIT_0__store_unsigned_int$left_STA_0$right_STA_1 = 183,
    _1_ELFHash__load_void_star$left_STA_0$result_STA_0__PlusPI_void_star_unsigned_long2void_star$left_STA_0$result_STA_0$right_STA_1__store_void_star$right_STA_0$left_STA_1 = 214,
    _1_ELFHash__BAnd_long_long2long$right_STA_0$result_STA_0$left_STA_1__convert_long2unsigned_int$left_STA_0$result_STA_0__local$result_STA_0$value_LIT_0__store_unsigned_int$left_STA_0$right_STA_1 = 163,
    _1_ELFHash__BXor_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1__BAnd_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1__local$result_STA_0$value_LIT_0__store_unsigned_int$left_STA_0$right_STA_1 = 134,
    _1_ELFHash__load_unsigned_int$left_STA_0$result_STA_0__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__Lt_unsigned_int_unsigned_int2int$left_STA_0$result_STA_0$right_STA_1__branchIfTrue$expr_STA_0$label_LAB_0 = 148,
    _1_ELFHash__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__constant_unsigned_int$result_STA_0$value_LIT_0 = 50,
    _1_ELFHash__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__constant_unsigned_int$result_STA_0$value_LIT_0__Ne_unsigned_int_unsigned_int2int$right_STA_0$result_STA_0$left_STA_1__branchIfTrue$expr_STA_0$label_LAB_0 = 187
} ;
extern int fcntl(int filedes , int cmd  , ...) ;
extern int fclose(void *stream ) ;
extern int pthread_cond_wait(int *cond , int *mutex ) ;
extern void perror(char const   *str ) ;
extern int pthread_cond_init(int *cond , int *attr ) ;
extern int write(int filedes , void *buf , unsigned int nbyte ) ;
extern int ptrace(int request , void *pid , void *addr , int data ) ;
extern float strtof(char const   *str , char const   *endptr ) ;
extern unsigned int strnlen(char const   *s , unsigned int maxlen ) ;
struct timeval {
   long tv_sec ;
   long tv_usec ;
};
extern void qsort(void *base , unsigned int nel , unsigned int width , int (*compar)(void *a ,
                                                                                     void *b ) ) ;
extern long clock(void) ;
extern long time(long *tloc ) ;
unsigned char _1_ELFHash_$array[1][220]  = { {        _1_ELFHash__constant_unsigned_int$result_STA_0$value_LIT_0__local$result_STA_0$value_LIT_0__store_unsigned_int$left_STA_0$right_STA_1,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)12,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_ELFHash__constant_unsigned_int$result_STA_0$value_LIT_0__local$result_STA_0$value_LIT_0__store_unsigned_int$left_STA_0$right_STA_1,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)16,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_ELFHash__constant_unsigned_int$result_STA_0$value_LIT_0__local$result_STA_0$value_LIT_0__store_unsigned_int$left_STA_0$right_STA_1,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        (unsigned char)20, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_ELFHash__constant_unsigned_int$result_STA_0$value_LIT_0__local$result_STA_0$value_LIT_0__store_unsigned_int$left_STA_0$right_STA_1, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)20,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            _1_ELFHash__goto$label_LAB_0,        (unsigned char)4,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_ELFHash__formal$result_STA_0$value_LIT_0,        (unsigned char)1,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_ELFHash__load_unsigned_int$left_STA_0$result_STA_0__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__Lt_unsigned_int_unsigned_int2int$left_STA_0$result_STA_0$right_STA_1__branchIfTrue$expr_STA_0$label_LAB_0,        (unsigned char)20, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        (unsigned char)18, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_ELFHash__goto$label_LAB_0, 
            (unsigned char)4,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            _1_ELFHash__goto$label_LAB_0,        (unsigned char)153,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_ELFHash__constant_int$result_STA_0$value_LIT_0__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__Shiftlt_unsigned_int_int2unsigned_int$left_STA_0$result_STA_0$right_STA_1,        (unsigned char)4,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)12,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_ELFHash__formal$result_STA_0$value_LIT_0,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_ELFHash__load_void_star$left_STA_0$result_STA_0__load_char$left_STA_0$result_STA_0__convert_char2unsigned_int$left_STA_0$result_STA_0__PlusA_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1__local$result_STA_0$value_LIT_0, 
            (unsigned char)12,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            _1_ELFHash__store_unsigned_int$left_STA_0$right_STA_1__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__convert_unsigned_int2long$left_STA_0$result_STA_0__constant_long$result_STA_0$value_LIT_0,        (unsigned char)12,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)240,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_ELFHash__BAnd_long_long2long$right_STA_0$result_STA_0$left_STA_1__convert_long2unsigned_int$left_STA_0$result_STA_0__local$result_STA_0$value_LIT_0__store_unsigned_int$left_STA_0$right_STA_1,        (unsigned char)16,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_ELFHash__goto$label_LAB_0,        (unsigned char)4, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_ELFHash__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__constant_unsigned_int$result_STA_0$value_LIT_0__Ne_unsigned_int_unsigned_int2int$right_STA_0$result_STA_0$left_STA_1__branchIfTrue$expr_STA_0$label_LAB_0, 
            (unsigned char)16,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)17,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            _1_ELFHash__goto$label_LAB_0,        (unsigned char)27,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_ELFHash__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__constant_int$result_STA_0$value_LIT_0,        (unsigned char)12,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)16,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)24,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_ELFHash__Shiftrt_unsigned_int_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1__BXor_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1__local$result_STA_0$value_LIT_0__store_unsigned_int$left_STA_0$right_STA_1,        (unsigned char)12, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_ELFHash__goto$label_LAB_0, 
            (unsigned char)4,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            _1_ELFHash__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__constant_unsigned_int$result_STA_0$value_LIT_0,        (unsigned char)12,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)16,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)255,        (unsigned char)255,        (unsigned char)255, 
            (unsigned char)255,        _1_ELFHash__BXor_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1__BAnd_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1__local$result_STA_0$value_LIT_0__store_unsigned_int$left_STA_0$right_STA_1,        (unsigned char)12,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_ELFHash__formal$result_STA_0$value_LIT_0,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_ELFHash__constant_unsigned_long$result_STA_0$value_LIT_0__constant_int$result_STA_0$value_LIT_0__convert_int2unsigned_long$left_STA_0$result_STA_0__Mult_unsigned_long_unsigned_long2unsigned_long$left_STA_0$result_STA_0$right_STA_1, 
            (unsigned char)1,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)1,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            _1_ELFHash__formal$result_STA_0$value_LIT_0,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_ELFHash__load_void_star$left_STA_0$result_STA_0__PlusPI_void_star_unsigned_long2void_star$left_STA_0$result_STA_0$right_STA_1__store_void_star$right_STA_0$left_STA_1,        _1_ELFHash__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__constant_unsigned_int$result_STA_0$value_LIT_0__PlusA_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1__local$result_STA_0$value_LIT_0,        (unsigned char)20, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        (unsigned char)1, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        (unsigned char)20, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_ELFHash__store_unsigned_int$left_STA_0$right_STA_1, 
            _1_ELFHash__goto$label_LAB_0,        (unsigned char)92,        (unsigned char)255,        (unsigned char)255, 
            (unsigned char)255,        _1_ELFHash__goto$label_LAB_0,        (unsigned char)87,        (unsigned char)255, 
            (unsigned char)255,        (unsigned char)255,        _1_ELFHash__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0,        (unsigned char)12, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_ELFHash__return_unsigned_int$expr_STA_0}};
extern int rand() ;
extern int read(int filedes , void *buf , unsigned int nbyte ) ;
extern int strcmp(char const   *a , char const   *b ) ;
extern void *fopen(char const   *filename , char const   *mode ) ;
extern double sqrt(double x ) ;
extern long strtol(char const   *str , char const   *endptr , int base ) ;
extern int snprintf(char *str , unsigned int size , char const   *format  , ...) ;
extern void *malloc(unsigned int size ) ;
extern int nanosleep(int *rqtp , int *rmtp ) ;
extern int pthread_mutex_unlock(int *mutex ) ;
extern int pthread_create(void *thread , void *attr , void *start_routine , void *arg ) ;
extern int atoi(char const   *s ) ;
extern int fseek(struct _IO_FILE *stream , long offs , int whence ) ;
extern int fscanf(struct _IO_FILE *stream , char const   *format  , ...) ;
void megaInit(void) ;
unsigned int ELFHash(char *str , unsigned int len ) 
{ 
  char _1_ELFHash_$locals[24] ;
  union _1_ELFHash_$node _1_ELFHash_$stack[1][32] ;
  union _1_ELFHash_$node *_1_ELFHash_$sp[1] ;
  unsigned char *_1_ELFHash_$pc[1] ;
  unsigned char _1_ELFHash_$currentOp ;

  {
  _1_ELFHash_$sp[0] = _1_ELFHash_$stack[0];
  _1_ELFHash_$pc[0] = _1_ELFHash_$array[0];
  while (1) {
    _1_ELFHash_$currentOp = *(_1_ELFHash_$pc[0]);
    if (_1_ELFHash_$currentOp == _1_ELFHash__BAnd_long_long2long$right_STA_0$result_STA_0$left_STA_1__convert_long2unsigned_int$left_STA_0$result_STA_0__local$result_STA_0$value_LIT_0__store_unsigned_int$left_STA_0$right_STA_1) {
      (_1_ELFHash_$pc[0]) ++;
      (_1_ELFHash_$sp[0] + -1)->_long = (_1_ELFHash_$sp[0] + -1)->_long & (_1_ELFHash_$sp[0] + 0)->_long;
      (_1_ELFHash_$sp[0] + -1)->_unsigned_int = (unsigned int )(_1_ELFHash_$sp[0] + -1)->_long;
      (_1_ELFHash_$sp[0] + 0)->_void_star = (void *)(_1_ELFHash_$locals + *((int *)_1_ELFHash_$pc[0]));
      *((unsigned int *)(_1_ELFHash_$sp[0] + 0)->_void_star) = (_1_ELFHash_$sp[0] + -1)->_unsigned_int;
      _1_ELFHash_$sp[0] += -2;
      _1_ELFHash_$pc[0] += 4;
    } else
    if (_1_ELFHash_$currentOp == _1_ELFHash__constant_unsigned_int$result_STA_0$value_LIT_0__local$result_STA_0$value_LIT_0__store_unsigned_int$left_STA_0$right_STA_1) {
      (_1_ELFHash_$pc[0]) ++;
      (_1_ELFHash_$sp[0] + 1)->_unsigned_int = *((unsigned int *)_1_ELFHash_$pc[0]);
      (_1_ELFHash_$sp[0] + 2)->_void_star = (void *)(_1_ELFHash_$locals + *((int *)(_1_ELFHash_$pc[0] + 4)));
      *((unsigned int *)(_1_ELFHash_$sp[0] + 2)->_void_star) = (_1_ELFHash_$sp[0] + 1)->_unsigned_int;
      _1_ELFHash_$pc[0] += 8;
    } else
    if (_1_ELFHash_$currentOp == _1_ELFHash__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__constant_unsigned_int$result_STA_0$value_LIT_0) {
      (_1_ELFHash_$pc[0]) ++;
      (_1_ELFHash_$sp[0] + 1)->_void_star = (void *)(_1_ELFHash_$locals + *((int *)_1_ELFHash_$pc[0]));
      (_1_ELFHash_$sp[0] + 1)->_unsigned_int = *((unsigned int *)(_1_ELFHash_$sp[0] + 1)->_void_star);
      (_1_ELFHash_$sp[0] + 2)->_void_star = (void *)(_1_ELFHash_$locals + *((int *)(_1_ELFHash_$pc[0] + 4)));
      (_1_ELFHash_$sp[0] + 2)->_unsigned_int = *((unsigned int *)(_1_ELFHash_$sp[0] + 2)->_void_star);
      (_1_ELFHash_$sp[0] + 3)->_unsigned_int = *((unsigned int *)(_1_ELFHash_$pc[0] + 8));
      _1_ELFHash_$sp[0] += 3;
      _1_ELFHash_$pc[0] += 12;
    } else
    if (_1_ELFHash_$currentOp == _1_ELFHash__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__constant_unsigned_int$result_STA_0$value_LIT_0__Ne_unsigned_int_unsigned_int2int$right_STA_0$result_STA_0$left_STA_1__branchIfTrue$expr_STA_0$label_LAB_0) {
      (_1_ELFHash_$pc[0]) ++;
      (_1_ELFHash_$sp[0] + 1)->_void_star = (void *)(_1_ELFHash_$locals + *((int *)_1_ELFHash_$pc[0]));
      (_1_ELFHash_$sp[0] + 1)->_unsigned_int = *((unsigned int *)(_1_ELFHash_$sp[0] + 1)->_void_star);
      (_1_ELFHash_$sp[0] + 2)->_unsigned_int = *((unsigned int *)(_1_ELFHash_$pc[0] + 4));
      (_1_ELFHash_$sp[0] + 1)->_int = (_1_ELFHash_$sp[0] + 1)->_unsigned_int != (_1_ELFHash_$sp[0] + 2)->_unsigned_int;
      if ((_1_ELFHash_$sp[0] + 1)->_int) {
        _1_ELFHash_$pc[0] += *((int *)(_1_ELFHash_$pc[0] + 8));
      } else {
        _1_ELFHash_$pc[0] += 12;
      }
    } else
    if (_1_ELFHash_$currentOp == _1_ELFHash__goto$label_LAB_0) {
      (_1_ELFHash_$pc[0]) ++;
      _1_ELFHash_$pc[0] += *((int *)_1_ELFHash_$pc[0]);
    } else
    if (_1_ELFHash_$currentOp == _1_ELFHash__load_unsigned_int$left_STA_0$result_STA_0__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__Lt_unsigned_int_unsigned_int2int$left_STA_0$result_STA_0$right_STA_1__branchIfTrue$expr_STA_0$label_LAB_0) {
      (_1_ELFHash_$pc[0]) ++;
      (_1_ELFHash_$sp[0] + 0)->_unsigned_int = *((unsigned int *)(_1_ELFHash_$sp[0] + 0)->_void_star);
      (_1_ELFHash_$sp[0] + 1)->_void_star = (void *)(_1_ELFHash_$locals + *((int *)_1_ELFHash_$pc[0]));
      (_1_ELFHash_$sp[0] + 1)->_unsigned_int = *((unsigned int *)(_1_ELFHash_$sp[0] + 1)->_void_star);
      (_1_ELFHash_$sp[0] + 0)->_int = (_1_ELFHash_$sp[0] + 1)->_unsigned_int < (_1_ELFHash_$sp[0] + 0)->_unsigned_int;
      if ((_1_ELFHash_$sp[0] + 0)->_int) {
        _1_ELFHash_$pc[0] += *((int *)(_1_ELFHash_$pc[0] + 4));
      } else {
        _1_ELFHash_$pc[0] += 8;
      }
      (_1_ELFHash_$sp[0]) --;
    } else
    if (_1_ELFHash_$currentOp == _1_ELFHash__store_unsigned_int$left_STA_0$right_STA_1) {
      (_1_ELFHash_$pc[0]) ++;
      *((unsigned int *)(_1_ELFHash_$sp[0] + 0)->_void_star) = (_1_ELFHash_$sp[0] + -1)->_unsigned_int;
      _1_ELFHash_$sp[0] += -2;
    } else
    if (_1_ELFHash_$currentOp == _1_ELFHash__store_unsigned_int$left_STA_0$right_STA_1__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__convert_unsigned_int2long$left_STA_0$result_STA_0__constant_long$result_STA_0$value_LIT_0) {
      (_1_ELFHash_$pc[0]) ++;
      *((unsigned int *)(_1_ELFHash_$sp[0] + 0)->_void_star) = (_1_ELFHash_$sp[0] + -1)->_unsigned_int;
      (_1_ELFHash_$sp[0] + -1)->_void_star = (void *)(_1_ELFHash_$locals + *((int *)_1_ELFHash_$pc[0]));
      (_1_ELFHash_$sp[0] + -1)->_unsigned_int = *((unsigned int *)(_1_ELFHash_$sp[0] + -1)->_void_star);
      (_1_ELFHash_$sp[0] + -1)->_long = (long )(_1_ELFHash_$sp[0] + -1)->_unsigned_int;
      (_1_ELFHash_$sp[0] + 0)->_long = *((long *)(_1_ELFHash_$pc[0] + 4));
      _1_ELFHash_$pc[0] += 12;
    } else
    if (_1_ELFHash_$currentOp == _1_ELFHash__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__constant_int$result_STA_0$value_LIT_0) {
      (_1_ELFHash_$pc[0]) ++;
      (_1_ELFHash_$sp[0] + 1)->_void_star = (void *)(_1_ELFHash_$locals + *((int *)_1_ELFHash_$pc[0]));
      (_1_ELFHash_$sp[0] + 1)->_unsigned_int = *((unsigned int *)(_1_ELFHash_$sp[0] + 1)->_void_star);
      (_1_ELFHash_$sp[0] + 2)->_void_star = (void *)(_1_ELFHash_$locals + *((int *)(_1_ELFHash_$pc[0] + 4)));
      (_1_ELFHash_$sp[0] + 2)->_unsigned_int = *((unsigned int *)(_1_ELFHash_$sp[0] + 2)->_void_star);
      (_1_ELFHash_$sp[0] + 3)->_int = *((int *)(_1_ELFHash_$pc[0] + 8));
      _1_ELFHash_$sp[0] += 3;
      _1_ELFHash_$pc[0] += 12;
    } else
    if (_1_ELFHash_$currentOp == _1_ELFHash__Shiftrt_unsigned_int_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1__BXor_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1__local$result_STA_0$value_LIT_0__store_unsigned_int$left_STA_0$right_STA_1) {
      (_1_ELFHash_$pc[0]) ++;
      (_1_ELFHash_$sp[0] + -1)->_unsigned_int = (_1_ELFHash_$sp[0] + -1)->_unsigned_int >> (_1_ELFHash_$sp[0] + 0)->_int;
      (_1_ELFHash_$sp[0] + -2)->_unsigned_int = (_1_ELFHash_$sp[0] + -2)->_unsigned_int ^ (_1_ELFHash_$sp[0] + -1)->_unsigned_int;
      (_1_ELFHash_$sp[0] + -1)->_void_star = (void *)(_1_ELFHash_$locals + *((int *)_1_ELFHash_$pc[0]));
      *((unsigned int *)(_1_ELFHash_$sp[0] + -1)->_void_star) = (_1_ELFHash_$sp[0] + -2)->_unsigned_int;
      _1_ELFHash_$sp[0] += -3;
      _1_ELFHash_$pc[0] += 4;
    } else
    if (_1_ELFHash_$currentOp == _1_ELFHash__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0) {
      (_1_ELFHash_$pc[0]) ++;
      (_1_ELFHash_$sp[0] + 1)->_void_star = (void *)(_1_ELFHash_$locals + *((int *)_1_ELFHash_$pc[0]));
      (_1_ELFHash_$sp[0] + 1)->_unsigned_int = *((unsigned int *)(_1_ELFHash_$sp[0] + 1)->_void_star);
      (_1_ELFHash_$sp[0]) ++;
      _1_ELFHash_$pc[0] += 4;
    } else
    if (_1_ELFHash_$currentOp == _1_ELFHash__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__constant_unsigned_int$result_STA_0$value_LIT_0__PlusA_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1__local$result_STA_0$value_LIT_0) {
      (_1_ELFHash_$pc[0]) ++;
      (_1_ELFHash_$sp[0] + 1)->_void_star = (void *)(_1_ELFHash_$locals + *((int *)_1_ELFHash_$pc[0]));
      (_1_ELFHash_$sp[0] + 1)->_unsigned_int = *((unsigned int *)(_1_ELFHash_$sp[0] + 1)->_void_star);
      (_1_ELFHash_$sp[0] + 2)->_unsigned_int = *((unsigned int *)(_1_ELFHash_$pc[0] + 4));
      (_1_ELFHash_$sp[0] + 1)->_unsigned_int = (_1_ELFHash_$sp[0] + 1)->_unsigned_int + (_1_ELFHash_$sp[0] + 2)->_unsigned_int;
      (_1_ELFHash_$sp[0] + 2)->_void_star = (void *)(_1_ELFHash_$locals + *((int *)(_1_ELFHash_$pc[0] + 8)));
      _1_ELFHash_$sp[0] += 2;
      _1_ELFHash_$pc[0] += 12;
    } else
    if (_1_ELFHash_$currentOp == _1_ELFHash__formal$result_STA_0$value_LIT_0) {
      (_1_ELFHash_$pc[0]) ++;
      switch (*((int *)_1_ELFHash_$pc[0])) {
      case 1: 
      (_1_ELFHash_$sp[0] + 1)->_void_star = (void *)(& len);
      break;
      case 0: 
      (_1_ELFHash_$sp[0] + 1)->_void_star = (void *)(& str);
      break;
      }
      (_1_ELFHash_$sp[0]) ++;
      _1_ELFHash_$pc[0] += 4;
    } else
    if (_1_ELFHash_$currentOp == _1_ELFHash__load_void_star$left_STA_0$result_STA_0__PlusPI_void_star_unsigned_long2void_star$left_STA_0$result_STA_0$right_STA_1__store_void_star$right_STA_0$left_STA_1) {
      (_1_ELFHash_$pc[0]) ++;
      (_1_ELFHash_$sp[0] + 0)->_void_star = *((void **)(_1_ELFHash_$sp[0] + 0)->_void_star);
      (_1_ELFHash_$sp[0] + -1)->_void_star = (_1_ELFHash_$sp[0] + 0)->_void_star + (_1_ELFHash_$sp[0] + -1)->_unsigned_long;
      *((void **)(_1_ELFHash_$sp[0] + -2)->_void_star) = (_1_ELFHash_$sp[0] + -1)->_void_star;
      _1_ELFHash_$sp[0] += -3;
    } else
    if (_1_ELFHash_$currentOp == _1_ELFHash__constant_int$result_STA_0$value_LIT_0__local$result_STA_0$value_LIT_0__load_unsigned_int$left_STA_0$result_STA_0__Shiftlt_unsigned_int_int2unsigned_int$left_STA_0$result_STA_0$right_STA_1) {
      (_1_ELFHash_$pc[0]) ++;
      (_1_ELFHash_$sp[0] + 1)->_int = *((int *)_1_ELFHash_$pc[0]);
      (_1_ELFHash_$sp[0] + 2)->_void_star = (void *)(_1_ELFHash_$locals + *((int *)(_1_ELFHash_$pc[0] + 4)));
      (_1_ELFHash_$sp[0] + 2)->_unsigned_int = *((unsigned int *)(_1_ELFHash_$sp[0] + 2)->_void_star);
      (_1_ELFHash_$sp[0] + 1)->_unsigned_int = (_1_ELFHash_$sp[0] + 2)->_unsigned_int << (_1_ELFHash_$sp[0] + 1)->_int;
      (_1_ELFHash_$sp[0]) ++;
      _1_ELFHash_$pc[0] += 8;
    } else
    if (_1_ELFHash_$currentOp == _1_ELFHash__return_unsigned_int$expr_STA_0) {
      (_1_ELFHash_$pc[0]) ++;
      return ((_1_ELFHash_$sp[0] + 0)->_unsigned_int);
    } else
    if (_1_ELFHash_$currentOp == _1_ELFHash__load_void_star$left_STA_0$result_STA_0__load_char$left_STA_0$result_STA_0__convert_char2unsigned_int$left_STA_0$result_STA_0__PlusA_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1__local$result_STA_0$value_LIT_0) {
      (_1_ELFHash_$pc[0]) ++;
      (_1_ELFHash_$sp[0] + 0)->_void_star = *((void **)(_1_ELFHash_$sp[0] + 0)->_void_star);
      (_1_ELFHash_$sp[0] + 0)->_char = *((char *)(_1_ELFHash_$sp[0] + 0)->_void_star);
      (_1_ELFHash_$sp[0] + 0)->_unsigned_int = (unsigned int )(_1_ELFHash_$sp[0] + 0)->_char;
      (_1_ELFHash_$sp[0] + -1)->_unsigned_int = (_1_ELFHash_$sp[0] + -1)->_unsigned_int + (_1_ELFHash_$sp[0] + 0)->_unsigned_int;
      (_1_ELFHash_$sp[0] + 0)->_void_star = (void *)(_1_ELFHash_$locals + *((int *)_1_ELFHash_$pc[0]));
      _1_ELFHash_$pc[0] += 4;
    } else
    if (_1_ELFHash_$currentOp == _1_ELFHash__BXor_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1__BAnd_unsigned_int_unsigned_int2unsigned_int$right_STA_0$result_STA_0$left_STA_1__local$result_STA_0$value_LIT_0__store_unsigned_int$left_STA_0$right_STA_1) {
      (_1_ELFHash_$pc[0]) ++;
      (_1_ELFHash_$sp[0] + -1)->_unsigned_int = (_1_ELFHash_$sp[0] + -1)->_unsigned_int ^ (_1_ELFHash_$sp[0] + 0)->_unsigned_int;
      (_1_ELFHash_$sp[0] + -2)->_unsigned_int = (_1_ELFHash_$sp[0] + -2)->_unsigned_int & (_1_ELFHash_$sp[0] + -1)->_unsigned_int;
      (_1_ELFHash_$sp[0] + -1)->_void_star = (void *)(_1_ELFHash_$locals + *((int *)_1_ELFHash_$pc[0]));
      *((unsigned int *)(_1_ELFHash_$sp[0] + -1)->_void_star) = (_1_ELFHash_$sp[0] + -2)->_unsigned_int;
      _1_ELFHash_$sp[0] += -3;
      _1_ELFHash_$pc[0] += 4;
    } else
    if (_1_ELFHash_$currentOp == _1_ELFHash__constant_unsigned_long$result_STA_0$value_LIT_0__constant_int$result_STA_0$value_LIT_0__convert_int2unsigned_long$left_STA_0$result_STA_0__Mult_unsigned_long_unsigned_long2unsigned_long$left_STA_0$result_STA_0$right_STA_1) {
      (_1_ELFHash_$pc[0]) ++;
      (_1_ELFHash_$sp[0] + 1)->_unsigned_long = *((unsigned long *)_1_ELFHash_$pc[0]);
      (_1_ELFHash_$sp[0] + 2)->_int = *((int *)(_1_ELFHash_$pc[0] + 8));
      (_1_ELFHash_$sp[0] + 2)->_unsigned_long = (unsigned long )(_1_ELFHash_$sp[0] + 2)->_int;
      (_1_ELFHash_$sp[0] + 1)->_unsigned_long = (_1_ELFHash_$sp[0] + 2)->_unsigned_long * (_1_ELFHash_$sp[0] + 1)->_unsigned_long;
      (_1_ELFHash_$sp[0]) ++;
      _1_ELFHash_$pc[0] += 12;
    } else {

    }
  }
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
  tmp___0 = ELFHash((char *)str, (unsigned int )tmp);
  hash = tmp___0;
  if (hash == 184139465U) {
    printf((char const   */* __restrict  */)"You win!\n");
  }
  return (0);
}
}
void megaInit(void) 
{ 


  {

}
}
