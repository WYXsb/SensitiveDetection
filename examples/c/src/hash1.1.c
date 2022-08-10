#include "../include/hash1.1.h"
#include <stdio.h>
#include <unistd.h>

#define MAX 99999
/*********************************Global var used to save the digest*/

/*state[0] = A, state[1] = B, state[2] = C, state[3] = D, state[4] = E*/
static unsigned int sha1state[5];
const unsigned int STATE[5] = {0x10bec849, 0xfd76c314, 0xd4a32960, 0x676521d3, 0x8ef3c0c4};


/*********************************Define the function used in SHA-1*/
unsigned int f1(unsigned int B, unsigned int C, unsigned int D)
{
    return (B & C) | (~B & D);
}

unsigned int f2(unsigned int B, unsigned int C, unsigned int D)
{
    return B ^ C ^ D;
}

unsigned int f3(unsigned int B, unsigned int C, unsigned int D)
{
    return (B & C) | (B & D) | (C & D);
}

unsigned int f4(unsigned int B, unsigned int C, unsigned int D)
{
    return B ^ C ^ D;
}

/*********************************Init the global var unsigned int state[5]*/
void Init()
{
    sha1state[0] = 0x67452301;
    sha1state[1] = 0xefcdab89;
    sha1state[2] = 0x98badcfe;
    sha1state[3] = 0x10325476;
    sha1state[4] = 0xc3d2e1f0;
}
/*********************************the end of the function*/

unsigned int cls(unsigned int a, int step)
{
    unsigned int temp;
    

    temp = (a << step) | (a >> (32 - step));
    return temp;
}

/*********************************the function used to compute the 80 loops and save the result into the global var state[]*/
void shaTran(unsigned char *buf, unsigned int *state)
{
    int i, j;
    unsigned int A, B, C, D, E, temp;      /*the Register "A,B,C,D,E" and temp*/
    unsigned int K[4];                     /*the K[t] used in SHA-1*/
    unsigned int W[80];                    /*the W[t] used in SHA-1*/
    unsigned char *p = (unsigned char *)W; /*the (unsigned char *)p point to W[0]*/

    /*********************************init the Register "A,B,C,D,E"*/
    A = sha1state[0];
    B = sha1state[1];
    C = sha1state[2];
    D = sha1state[3];
    E = sha1state[4];

    /*********************************init K*/

    K[0] = 0x5a827999;
    K[1] = 0x6ed9eba1;
    K[2] = 0x8f1bbcdc;
    K[3] = 0xca62c1d6;

    /*********************************compute W[t]*/

    /*compute W[t] 0<=t<=15*/
    /*++++++++++++++++++++++++++++++++
    Notice that
    The IA32 System use little-endian to save data in Main Memory
    So change the sequence before use it
    ++++++++++++++++++++++++++++++++*/
    for (i = 0; i < 16; i++)
    {
        j = 4 * i;
        p[j + 3] = buf[j];
        p[j + 2] = buf[j + 1];
        p[j + 1] = buf[j + 2];
        p[j] = buf[j + 3];
    }

    /*compute W[t] 16<=t<=79*/
    for (i = 16; i < 80; i++)
    {
        
        W[i] = W[i - 16] ^ W[i - 14] ^ W[i - 8] ^ W[i - 3];
        W[i] = cls(W[i], 1);
    }

    /*********************************compute 1st loop*/
    for (i = 0; i < 20; i++)
    {
        
        temp = A;
        A = E;
        E = B;
        B = temp;
        //A=E,B=A
        temp = C;
        C = E;
        //C = B
        E = D;
        D = temp;
        //d = c;
        

        A = A + f1(C, D, E) + cls(B, 5) + W[i] + K[0];
        C = cls(C, 30);
    }

    /*********************************compute 2nd loop*/
    for (i = 20; i < 40; i++)
    {
        temp = A;
        A = E;
        E = B;
        B = temp;
        //A=E,B=A
        temp = C;
        C = E;
        //C = B
        E = D;
        D = temp;
        //d = c;

        A = A + f2(C, D, E) + cls(B, 5) + W[i] + K[1];
        C = cls(C, 30);
    }

    /*********************************compute 3rd loop*/
    for (i = 40; i < 60; i++)
    {
        temp = A;
        A = E;
        E = B;
        B = temp;
        //A=E,B=A
        temp = C;
        C = E;
        //C = B
        E = D;
        D = temp;
        //d = c;

        A = A + f3(C, D, E) + cls(B, 5) + W[i] + K[2];
        C = cls(C, 30);
    }

    /*********************************compute 4th loop*/
    for (i = 60; i < 80; i++)
    {
        
        temp = A;
        A = E;
        E = B;
        B = temp;
        //A=E,B=A
        temp = C;
        C = E;
        //C = B
        E = D;
        D = temp;
        //d = c;

        A = A + f4(C, D, E) + cls(B, 5) + W[i] + K[3];
        C = cls(C, 30);
    }

    /*********************************add the vars back into the global var state[]*/
    sha1state[0] += A;
    sha1state[1] += B;
    sha1state[2] += C;
    sha1state[3] += D;
    sha1state[4] += E;
}
/*********************************the end of the function*/

/*********************************the function used to padding*/
void sha(unsigned char *buf, int len, unsigned int *state, unsigned int f1, unsigned int f2)
{
    int i;
    unsigned int floop1, floop2; /*use floop1:floop2 to represent the length of the file in bit*/
    unsigned char flen[8];       /*use unsigned char flen[8] to transform the floop1:floop2 in last block*/
    unsigned char *p1 = (unsigned char *)&floop1;
    unsigned char *p2 = (unsigned char *)&floop2;
    floop1 = f1;
    floop2 = f2;
    floop2 = floop2 + (unsigned int)(len * 8); 
    
    /*add the last block's length(in bit)*/

    /*********************************compute the whole file's length*/

    /*compute the length of the file and save it into unsigned char flen[8]*/
    /*++++++++++++++++++++++++++++++++
    Notice that
    The IA32 System use little-endian to save data in Main Memory
    So change the sequence before use it
    ++++++++++++++++++++++++++++++++*/
    // printf("floop1 = %08x\n", floop1);
    // printf("floop2 = %08x\n", floop2);
    for (i = 0; i < 4; i++)
    {
        flen[3 - i] = *p1;
        flen[7 - i] = *p2;
        p1++;
        p2++;
    }

    /*********************************do the padding*/
    /*the file's length(bit) < 448 */
    if (len < 56)
    {
        /*pad it like 1000000...(bit) from the end(buf[len-1]) to the buf[55]*/
        buf[len] = 0x80;
        for (i = len + 1; i < 56; i++)
        {
            buf[i] = 0x00;
        }

        /*pad the last 64bit using flen[8](the length of the file computed before)*/
        for (i = 56; i < 64; i++)
        {
            buf[i] = flen[i - 56];
        }

        /*then call the function "shaTran" to do the loop*/
        shaTran(buf, state);
    }

    /*the file's length(bit) >= 448 */
    else
    {
        /*pad the 1st block with a number of bit 100000... until the end of the buf(buf[63])*/
        buf[len] = 0x80;
        for (i = len + 1; i < 64; i++)
        {
            buf[i] = 0x00;
        }

        /*call the function "shaTran" to do the loop*/
        shaTran(buf, state);

        /*pad the 1st block with a number of bit 000000... until the 448 bit(buf[55])*/
        for (i = 0; i < 56; i++)
            buf[i] = 0x00;

        /*pad the last 64bit using flen[8](the length of the file computed before)*/
        for (i = 56; i < 64; i++)
        {
            buf[i] = flen[i - 56];
        }

        /*call the function "shaTran" to do the loop*/
        shaTran(buf, state);
    }
}
/*********************************the end of the function*/

int sha1(char* buff,char* pid,unsigned int finalstate[5])
{
    unsigned char buf[64]; /*the input block of SHA-1*/
    FILE *file;
    FILE *writeFile;
    int len;                     /*used to save the length of one read from the file (byte)*/
    unsigned int floop1, floop2; /*use floop1:floop2 to represent the length of the file in bit*/
    floop1 = floop2 = 0;         /*at 1st make them equal 0*/
    char comm[128];
    struct stat st;

    /*********************************Init the global var*/
    Init();
    stat(buff,&st);
    if (S_ISDIR(st.st_mode))
    {
        printf("is a dir\n");
        return 1;
    }
        
    /*********************************can not open file error*/
    if (!(file = fopen(buff, "r")))
    {
        printf("can not open file!!!%s\n",buff);
        return -1;
    }
    

    /*********************************read data from the file*/
    while (!feof(file))
    {
        /*********************************each time read 64 bits into buf at most*/
        len = fread(buf, 1, 64, file); /*len used to save the length of each read*/

        /*********************************read file error*/
        if (ferror(file))
        {
            printf("read file error!!!\n");
            return -1;
        }

        /*********************************the buf[64] is full*/
        if (len == 64)
        {
            /*use 2 unsigned int to represent 1 64bit number, floop1:floop2*/
            if ((floop1 == 0xffffffff) && (floop2 == 0xfffffe00))
            {
                printf("file larger than 2exp(64)");
                return -1;
            }
            if (floop2 != 0xfffffe00)
                floop2 += 512;
            else
            {
                floop1++;
                floop2 = 0;
            }

            /*call the function "shaTran" to do the loop*/
            shaTran(buf, sha1state);
        }

        /*********************************less than 512 bits need to pad*/
        else
        {
            /*call the function "sha" to do the padding and other compute*/
            sha(buf, len, sha1state, floop1, floop2);
        }
    }
    for(int i = 0; i < 5; i++)
    {
        finalstate[i] = sha1state[i];
    }
    /*********************************print the digest*/
    //printf("%s\n",buff);
    //printf("%08x%08x%08x%08x%08x\n", state[0], state[1], state[2], state[3], state[4]);
    //printf("warning mining process %s killed\n",pid);
    //sprintf(comm, "/home/wyx/XBash-malware-files/cmp %08x%08x%08x%08x%08x %s", state[0],state[1],state[2],state[3],state[4],pid); // 产⽣"123
    //system(comm);
    return 0;
}
int getRootpath(char *rootpath,char *path,char *pid,unsigned int finalstate[5])
{
    int pathlen;
    char cwd[1024];
    char linkpath[1024];
    char Relativepath[1024]={0};
    if (path[0] == '/')
    {
        // sprintf(rootpath,"/proc/%s/root%s",pid,path);
        //printf("%s\n", path);
        return sha1(path,pid,finalstate); 
        
    } 
    else if (path[0] == '.' && path[1] == '/')
    {
        pathlen = strlen(path);
        for (int i = 0; i < pathlen; i++)
        {
            Relativepath[i] = path[i+1];
        }
        sprintf(cwd, "/proc/%s/cwd", pid);
        readlink(cwd, linkpath, 1024 - 1);
        sprintf(rootpath, "%s%s", linkpath,Relativepath);
        //printf("rootpath:%s\nrelvpath:%s\n",linkpath,Relativepath);
        return sha1(rootpath,pid,finalstate);
    }
    else
    {
        sprintf(cwd, "/proc/%s/cwd", pid);
        readlink(cwd, linkpath, 1024 - 1);
        sprintf(rootpath, "%s/%s", linkpath,path);
        //printf("rootpath:%s\nrelvpath:%s\n",linkpath,path);
        // printf("%s\n",rootpath);
        return sha1(rootpath, pid, finalstate);
    }
}

// int main(int argc,char *argv[])
// {
//     char buf[128][512];
//     char *path;
//     char rootpath[512];
//     char *pid ;
//     int len = 0;
//     int pathlen;
//     const int filePosition = 53;
//     const int typePosition = 26;
//     if(argc < 3)
//     {
//         printf("no enough parameter\n");
//         return -1;
//     }
//     path = argv[1];
//     pid = argv[2];
//     char inroot[18] = {0};
//     if(strlen(path) >= 11)
//     {
//         memcpy(inroot,path,11);
//         if(!strcmp(inroot,"/proc/self/"))
//         {
//             return 0;
//         }
//     }
//     getRootpath(rootpath,path,pid);
//     //printf("%s\n",path);
    

// }
