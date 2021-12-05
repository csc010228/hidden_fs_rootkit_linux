mountinfo_fs_num=$(wc -l /proc/self/mountinfo | tr -cd [:digit:])
make
mkdir a
mkdir b
sudo insmod detect_hidden_fs.ko
sudo mount --bind ./a ./b
sudo rmmod detect_hidden_fs
sudo umount ./b
rm -rf a
rm -rf b
real_fs_num=$(dmesg | grep "detected fs:" | tail -1)
real_fs_num=${real_fs_num##*:}
if [ "$real_fs_num" = "$mountinfo_fs_num" ];then
	echo "\nNo file system hidden(total file systems:$real_fs_num)!"
else
	echo "\nThere are some file systems hidden(file systems detected:$real_fs_num,but only see $mountinfo_fs_num in /proc/self/mountinfo)!"
fi
