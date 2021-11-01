# hidden_fs_rootkit_linux

隐藏文件系统(hidden_fs)，利用了linux内核的lkm机制进行rootkit攻击，编写内核模块hook了三个系统调用open,openat，close和read，实现对/proc/self/mountinfo的部分信息的隐藏，从而达到隐藏某一个文件系统的目的

将代码下载下来之后，更改hidden_fs.c的宏定义HIDDEN_FS_FILE_PATH，将其更改为想要隐藏的文件系统的根目录，记得要在前后各加上一个空格  
然后依次执行如下命令：  
`make`  
`sudo insmod hidden_fs.ko`  
即可
