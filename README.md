# hidden_fs_rootkit_linux

隐藏文件系统(hidden_fs)，使用了linux内核的lkm机制，编写内核模块hook了三个系统调用openat，close和read，将其进行
