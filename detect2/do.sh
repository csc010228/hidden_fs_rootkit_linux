mountinfo_fs_num=$(wc -l /proc/self/mountinfo | tr -cd [:digit:])
make
sudo insmod detect.ko
cat /proc/self/mountinfo > ./mountinfo
sudo rmmod detect
sudo insmod detect.ko
cat /proc/self/mountinfo > ./mountinfo
sudo rmmod detect
real_fs_num=$(dmesg | grep "Detect file system num:" | tail -1)
real_fs_num=${real_fs_num##*:}
if [ "$real_fs_num" = "$mountinfo_fs_num" ];then
	echo "\nNo file system hidden(total file systems:$real_fs_num)!"
else
	echo "\nThere are some file systems hidden(file systems detected:$real_fs_num,but only see $mountinfo_fs_num in /proc/self/mountinfo)!"
fi
