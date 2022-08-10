#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>


unsigned int f1(unsigned int B, unsigned int C, unsigned int D);
unsigned int f2(unsigned int B, unsigned int C, unsigned int D);
unsigned int f3(unsigned int B, unsigned int C, unsigned int D);
unsigned int f4(unsigned int B, unsigned int C, unsigned int D);
void Init();
unsigned int cls(unsigned int a, int step);
void shaTran(unsigned char *buf, unsigned int *state);
void sha(unsigned char *buf, int len, unsigned int *state, unsigned int f1, unsigned int f2);
int sha1(char* buff,char* pid,unsigned int finalstate[5]);
int getRootpath(char *rootpath,char *path,char *pid,unsigned int finalstate[5]);