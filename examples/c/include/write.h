#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#define MAX 9999


int myread(char buf[][512],FILE *file);
void W(char *p, int left, int right); //快速排序,先去重
int pathfind(char *sepc, char *buf, FILE *file,int linessum,int Cachefirstlinelen);
int mywrite(char buf[MAX][512],int num,FILE *wfile);
int ModifyStr(char *retstr,char* path,char *SHA1);