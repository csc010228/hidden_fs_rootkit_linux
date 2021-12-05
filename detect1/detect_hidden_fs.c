#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/types.h>
#include <linux/fs_struct.h>
#include <linux/wait.h>
#include <linux/spinlock_types.h>
#include <linux/ns_common.h>
#include <linux/user_namespace.h>
#include <linux/nsproxy.h>
#include <asm-generic/int-ll64.h>
#include <asm/cache.h>

MODULE_LICENSE("GPL");


int sizeof_mnt_namespace,ok=0;
unsigned char * mnt_ns,*old_mnt_ns,*new_mnt_ns;



static int commit_tree_pre_handler(struct kprobe *p,struct pt_regs *regs)
{
	if(!ok)
	{
		memcpy(old_mnt_ns,mnt_ns,sizeof_mnt_namespace);
	}
	return 0;
}

static struct kprobe commit_tree_kp = {
    .symbol_name = "commit_tree",
    .pre_handler = commit_tree_pre_handler,
};




static int __attach_mnt_pre_handler(struct kprobe *p,struct pt_regs *regs)
{
	int i=0;
	memcpy(new_mnt_ns,mnt_ns,sizeof_mnt_namespace);
	if(!ok)
	{
		for(i=0;i<sizeof_mnt_namespace;i++)
		{
			if(new_mnt_ns[i]==(old_mnt_ns[i]+1))
			{
				ok=1;
				printk(KERN_ALERT "detected fs:%d\n",((int)new_mnt_ns[i])-2);
			}
		}
	}
	return 0;
}

static struct kprobe __attach_mnt_kp = {
    .symbol_name = "__attach_mnt",
    .pre_handler = __attach_mnt_pre_handler
};

/*模块的初始化函数，模块的入口函数，加载模块*/
static int __init init_detect_hidden_fs(void)
{
	unsigned int max_member_size=8;
	struct task_struct * cur=get_current();
	struct nsproxy * cur_nsproxy=cur->nsproxy;
	if(sizeof(struct ns_common)>max_member_size)
	{
		max_member_size=sizeof(struct ns_common);
	}
	if(sizeof(void *)>max_member_size)
	{
		max_member_size=sizeof(void *);
	}
	if(sizeof(struct list_head)>max_member_size)
	{
		max_member_size=sizeof(struct list_head);
	}
	if(sizeof(spinlock_t)>max_member_size)
	{
		max_member_size=sizeof(spinlock_t);
	}
	if(sizeof(u64)>max_member_size)
	{
		max_member_size=sizeof(u64);
	}
	if(sizeof(wait_queue_head_t)>max_member_size)
	{
		max_member_size=sizeof(wait_queue_head_t);
	}
	if(sizeof(unsigned int )>max_member_size)
	{
		max_member_size=sizeof(unsigned int );
	}
	sizeof_mnt_namespace=11*max_member_size;
	mnt_ns=(char *)cur_nsproxy->mnt_ns;
	old_mnt_ns=(char *)kvzalloc(sizeof_mnt_namespace,GFP_KERNEL);
	new_mnt_ns=(char *)kvzalloc(sizeof_mnt_namespace,GFP_KERNEL);
	register_kprobe(&commit_tree_kp);
	register_kprobe(&__attach_mnt_kp);
	return 0;
}

/*出口函数，卸载模块*/
static void __exit exit_detect_hidden_fs(void)
{
	unregister_kprobe(&commit_tree_kp);
	unregister_kprobe(&__attach_mnt_kp);
	kvfree(old_mnt_ns);
	kvfree(new_mnt_ns);
}

module_init(init_detect_hidden_fs);
module_exit(exit_detect_hidden_fs);
