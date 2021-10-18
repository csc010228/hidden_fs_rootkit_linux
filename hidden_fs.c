#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/time.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/fs.h>

MODULE_LICENSE("GPL");

unsigned long *sys_call_table = 0;			/*系统调用表的指针*/

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);		/* typedef for kallsyms_lookup_name() so we can easily cast kp.addr */
kallsyms_lookup_name_t kallsyms_lookup_name;		/*kallsyms_lookup_name_t函数指针*/

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

typedef long (*statfs_t)(const char * pathname,struct statfs *buf);
statfs_t orig_statfs;

asmlinkage long statfs_hook(const char * pathname,struct statfs *buf)
{
	typedef int (*do_statfs_native_t)(struct kstatfs *st, struct statfs *p);
	do_statfs_native_t do_statfs_native=kallsyms_lookup_name("do_statfs_native");

	struct kstatfs st;
	int error = user_statfs(pathname, &st);
	if (!error)
		error = do_statfs_native(&st, buf);
	printk("statfs\n");
	return error;
}


/*
获取kallsyms_lookup_name函数指针
*/
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
static void get_kallsyms_lookup_name(void) {
  	/* register the kprobe */
  	register_kprobe(&kp);

  	/* assign kallsyms_lookup_name symbol to kp.addr */
  	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    
  	/* done with the kprobe, so unregister it */
  	unregister_kprobe(&kp);
}

/*模块的初始化函数，模块的入口函数，加载模块*/
static int __init init_hidden_fs(void)
{
	int orig_cr0;		/*原始cr0寄存器的值*/
	printk("My syscall is starting。。。\n");
	get_kallsyms_lookup_name();
	sys_call_table=(unsigned long *) kallsyms_lookup_name("sys_call_table");			/* 获取系统调用服务首地址 */
   	printk("sys_call_table: 0x%p\n", sys_call_table);
	orig_statfs=(statfs_t)(sys_call_table[__NR_statfs]);		/* 保存原始系统调用 */
	orig_cr0 = set_cr0_16_0();	/* 设置cr0可更改 */
	sys_call_table[__NR_statfs]=(unsigned long int)statfs_hook;		/* 更改原始的系统调用服务地址 */
	setback_cr0(orig_cr0);	/* 设置为原始的只读cr0 */
	return 0;
}

/*出口函数，卸载模块*/
static void __exit exit_hidden_fs(void)
{
	int orig_cr0;		/*原始cr0寄存器的值*/
 	orig_cr0 = set_cr0_16_0();	/* 设置cr0中对sys_call_table的更改权限 */
	sys_call_table[__NR_statfs]=(unsigned long int)orig_statfs;			/*恢复原始系统调用*/
    setback_cr0(orig_cr0);	/* 恢复原有的中断向量表中的函数指针的值 */
   	printk("My syscall exit....\n");	/* 恢复原有的cr0的值 */
}

module_init(init_hidden_fs);
module_exit(exit_hidden_fs);