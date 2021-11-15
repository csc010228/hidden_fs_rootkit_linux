#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/types.h>

MODULE_LICENSE("GPL");


typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);		/* typedef for kallsyms_lookup_name() so we can easily cast kp.addr */
kallsyms_lookup_name_t kallsyms_lookup_name_p;		/*kallsyms_lookup_name_t函数指针*/

/*
设置cr0寄存器的第16位为0，并把原始的cr0寄存器的值返回
*/
unsigned int set_cr0_16_0(void)	
{
   	unsigned int cr0 = 0;
   	unsigned int ret;
    /* 前者用在32位系统。后者用在64位系统，本系统64位 */
    //asm volatile ("movl %%cr0, %%eax" : "=a"(cr0));	
   	asm volatile ("movq %%cr0, %%rax" : "=a"(cr0));	/* 将cr0寄存器的值移动到rax寄存器中，同时输出到cr0变量中 */
    ret = cr0;
	cr0 &= 0xfffeffff;	/* 将cr0变量值中的第16位清0，将修改后的值写入cr0寄存器 */
	//asm volatile ("movl %%eax, %%cr0" :: "a"(cr0));
	asm volatile ("movq %%rax, %%cr0" :: "a"(cr0));	/* 读取cr0的值到rax寄存器，再将rax寄存器的值放入cr0中 */
	return ret;
}

/*
读取val的值到rax寄存器，再将rax寄存器的值放入cr0中
*/
void setback_cr0(unsigned int val)
{	

	//asm volatile ("movl %%eax, %%cr0" :: "a"(val));
	asm volatile ("movq %%rax, %%cr0" :: "a"(val));
}

static int fs_num=0;
static int tag=0;

/*

*/
static struct kprobe show_mountinfo_kp = {
    .symbol_name = "show_mountinfo"
};

static int show_mountinfo_handler_pre(struct kprobe * p,struct pt_regs * regs)
{
	fs_num++;
	//printk(KERN_INFO "SHOW_MOUNTINFO");
	return 0;
}

static struct kprobe mountinfo_open_kp = {
    .symbol_name = "mountinfo_open"
};

static int mountinfo_open_handler_pre(struct kprobe * p,struct pt_regs * regs)
{
	int ret;
	printk(KERN_ALERT "MOUNTINFO_OPEN");
	show_mountinfo_kp.pre_handler=show_mountinfo_handler_pre;
   	ret=register_kprobe(&show_mountinfo_kp);
   	if(ret<0)
   	{
   		printk(KERN_ALERT "Register show_mountinfo kprobe error");
   		return ret;
   	}
   	tag=1;
   	return 0;
}

/*模块的初始化函数，模块的入口函数，加载模块*/
static int __init init_detect_hidden_fs(void)
{
	int ret;
   	/*show_mountinfo_kp.pre_handler=show_mountinfo_handler_pre;
   	ret=register_kprobe(&show_mountinfo_kp);
   	if(ret<0)
   	{
   		printk(KERN_INFO "Register kprobe error");
   		return ret;
   	}*/
   	mountinfo_open_kp.pre_handler=mountinfo_open_handler_pre;
   	ret=register_kprobe(&mountinfo_open_kp);
   	if(ret<0)
   	{
   		printk(KERN_ALERT "Register mountinfo_open kprobe error");
   		return ret;
   	}
	return 0;
}

/*出口函数，卸载模块*/
static void __exit exit_detect_hidden_fs(void)
{
	if(tag)
	{
		unregister_kprobe(&show_mountinfo_kp);
	}
	unregister_kprobe(&mountinfo_open_kp);
	printk(KERN_ALERT "Detect file system num:%d",fs_num-2);
}

module_init(init_detect_hidden_fs);
module_exit(exit_detect_hidden_fs);
