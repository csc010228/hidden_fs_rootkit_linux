# hidden_fs_rootkit_linux

隐藏文件系统(hidden_fs)，利用了linux内核的lkm机制进行rootkit攻击，编写内核模块hook了四个系统调用open，openat，close和read，实现对/proc/self/mountinfo的部分信息的隐藏，从而达到隐藏某一个文件系统的目的

将代码下载下来之后，更改hidden_fs.c的宏定义HIDDEN_FS_FILE_PATH，将其更改为想要隐藏的文件系统的根目录，记得要在前后各加上一个空格  
然后依次执行如下命令：  
`make`  
`sudo insmod hidden_fs.ko`  
即可

detect1和detect2这两个目录下的文件是用于隐藏文件系统检测的,首选使用detect1进行检测,如果detetc1没有奏效,那么再考虑用detect2进行检测

使用detect1下的方法检测的方法就是进入detect1目录,然后运行sh do.sh
使用detect2下的方法检测的方法就是进入detect2目录,然后运行sh detect.sh
