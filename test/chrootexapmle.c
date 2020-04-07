#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

int main(void)
{
    char chroot_path[] = "/tmp";
    char *pwd;
    int ret;

    /*chroot 需要root权限*/
    ret = chroot(chroot_path);
    if (ret != 0) {
        perror("chroot:");
        exit(-1);
    }
    pwd = getcwd(NULL, 80);
    printf("After chroot,getcwd is [%s]\n",pwd);
    free(pwd);

    /*可以建立/tmp/test，测试一下是否可以改变目录 /tmp/test <==> /test*/
    ret = chdir("/test");
    if( ret < 0 )
    {
            perror("chdir /test");
            //exit(-1);
    }
    else
         /*由于chroot之后，当前工作目录还没有改变，所以需要再调用chdir来改变到/目录*/
         if( chdir("/") < 0 )
         {
                 perror("chdir /");
                 exit(-1);
         }
    rmdir("/test");
    pwd = getcwd(NULL, 80);
    printf("After chdir /,getcwd is [%s]\n",pwd);
    free(pwd);

    return 0;
}