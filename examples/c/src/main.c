#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include "../include/cmp.h"
#include "../include/hash1.1.h"
#include "../include/write.h"
#include "../include/main.h"



int detect(char *path, char *pid)
{
    char buf[MAX] = {0};
    char comm[256] = {0}; 
    char SHA1[41];
    FILE *file;
    char buf1[128][512];
    unsigned int finalstate[5] = {0};
    int sum;
    int sumlen;
    char sepc[MAX];
    char filenum[64];     //文件中总项数
    char filebuf[MAX][512];
    FILE *wfile;
    char rootpath[512];
    int len = 0;
    int num;
    int pathlen = 64; //缓存项中文件名长度
    int alllen = 106; //文件缓存项（一行的）长度（除去后面的时间）
    int all_len = 113; //文件缓存项（一行的）长度（包括后面的时间）
    int lineposition; //在Cache中找到缓存的在的行标
    // const int filePosition = 53;//在
    // const int typePosition = 26;//

    time_t tmpcal_t;
    struct tm *tmp_ptr = NULL;
    time(&tmpcal_t);
	tmp_ptr = localtime(&tmpcal_t);
    int time1 = 0;
    int timenow = 0;

    /* path如果小于64字节，填充空格至64 ，填充后的路径存到sepc中，pid参数无用*/
    if (ModifyStr(sepc, path, pid) == -1)
    {
        return -1;
    }

    /****** 查找缓存 *****/
    wfile = fopen("TimeCache", "r+");
    fgets(filenum, 512, wfile);
    //printf("%s", filenum);
    sum = atoi(filenum);
    //printf("sum:%d\n",sum);
    sumlen = strlen(filenum);
    if ((lineposition = pathfind(sepc, buf, wfile,sum,sumlen) )== 0)
    {
        // cache中没找到相应的文件
        fseek(wfile, sumlen, SEEK_SET);
        num = myread(filebuf, wfile);
        /****计算HASH值*****/
        //printf("%s\n",path);
        getRootpath(rootpath, path, pid,finalstate);
        sprintf(sepc + pathlen, "%08x%08x%08x%08x%08x  %02d%02d%02d\n", finalstate[0], finalstate[1], finalstate[2], finalstate[3], finalstate[4],\
        tmp_ptr->tm_hour, tmp_ptr->tm_min, tmp_ptr->tm_sec);

        //printf("sepc:%s",buf);
        sprintf(SHA1, "%s", buf + pathlen);
        strcpy(filebuf[num - 1], sepc);
        mywrite(filebuf, num, wfile);
        //printf("SHA1:%s\nsepc:%s",SHA1,sepc);
    }
    else
    {
        // printf("buf:%s",buf);
        // printf("len:%ld\n",strlen(buf));

        //printf("line:%d\n",lineposition);
        /****** 获得当前时间 *****/
        time1 = atoi(buf+alllen);
        //printf("time:%6d\n",time1);
        timenow = tmp_ptr->tm_hour * 10000 + tmp_ptr->tm_min * 100 + tmp_ptr->tm_sec;
        //printf("timenow:%6d\n",timenow);
        if(timenow - time1 > 300 || timenow - time1 < -300)
        {   

            getRootpath(rootpath, path, pid,finalstate);
            sprintf(buf + pathlen, "%08x%08x%08x%08x%08x  %02d%02d%02d\n", finalstate[0], finalstate[1], finalstate[2], finalstate[3], finalstate[4],\
            tmp_ptr->tm_hour, tmp_ptr->tm_min, tmp_ptr->tm_sec);
            fseek(wfile, sumlen + lineposition * all_len, SEEK_SET);
            //printf("%ld\n",strlen(buf));
            fwrite(buf,sizeof(char),strlen(buf),wfile);
        }
        //printf("buf:%s",buf);
        sprintf(SHA1, "%s", buf + pathlen);
    }
    

    
    //printf("SHA1:%s\n", SHA1);
    /****** 特征匹配 *****/
    file = fopen("hash.txt", "r");
    fgets(buf, 17, file);
    sum = atoi(buf);
    // printf("%s\n",argv[1]);
    sumlen = strlen(buf);
    //printf("sum:%d sumlen:%d\n",sum,sumlen);

    for (int i = 0; i < sumlen - 1; i++)
    {
        if (buf[i] < 48 || buf[i] > 57)
        {
            printf("sum error");
            return -1;
        }
    }
    //printf("SHA1:%s",SHA1);
    // printf("%s\n",argv[1]);
    // fgets(buf,42,file);
    if (find(SHA1, buf, file,sum,sumlen))
    {
        printf("find mining process hash:%s pid:%s\n", buf, pid);
        // sprintf(comm, "kill %s", pid);
        // system(comm);
    }
    fclose(file);
    fclose(wfile);
    return 0;
}