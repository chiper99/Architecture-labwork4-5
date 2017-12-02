#include<linux/init.h>
#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/errno.h>
#include<linux/types.h>
#include<linux/unistd.h>
#include<asm/cacheflush.h>
#include<asm/page.h>
#include<asm/current.h>
#include<linux/sched.h>
#include <linux/fs.h> 
#include<linux/kallsyms.h>
unsigned long *sys_call_table = (unsigned long *)0;
asmlinkage int (*original_open)(const char*,int);
int s=0;

char *getversion(void)
{
   struct file *f;
   static char *fname = "/proc/version";
   static char buff[501];
   static char ver[20];
   size_t x=0,y=0;
   size_t n;
   f = filp_open(fname,O_RDONLY,0);
   n = kernel_read(f,0,buff,500);
   if(n){
   buff[n]='\0';
   while(1){
   	if((buff[x]=='1')||(buff[x]=='2')||(buff[x]=='3')||(buff[x]=='4')||(buff[x]=='5')||(buff[x]=='6')||(buff[x]=='7')||(buff[x]=='8')||(buff[x]=='9'))break;
   	x++;
   }
   while(1){
	ver[y]=buff[x];
	y++;x++;
	if(buff[x]==' ')break;
   }
   ver[y]='\0';
   }
   filp_close(f,NULL);
   
   return ver;
}

char *getpath(char *version)
{
    static char path[100];
    strcpy(path,"/boot/System.map-");
    strcat(path,version);
    return path;
}

int getadress(char *path) 
{

   size_t n;
   int adress;
   struct file *f;
   f = filp_open(path,O_RDONLY,0);
   int SizeBuff = vfs_llseek(f,(off_t)0,SEEK_END);
   char *Buff = vmalloc(SizeBuff+1);
   char *str1,str2[10];
   n = kernel_read(f,0,Buff,SizeBuff);
   str1 = strstr(Buff,"sys_call_table\n")-11;
   strncpy(str2,str1,8);
   str2[8] = '\0'; 
   sscanf(str2,"%lx",&sys_call_table);
   return adress;
}

asmlinkage int new_open(const char *pathname, int flags)
{
s++;
if(s==30)
{
s=0;
printk(KERN_ALERT "INTERCEPTED Path: %s",pathname);
}
return (*original_open)(pathname, flags);
}

static int init(void) {
printk(KERN_ALERT "\nINIT\n");
getadress(getpath(getversion()));
write_cr0 (read_cr0 () & (~ 0x10000));
original_open = (void *)sys_call_table[__NR_open];
sys_call_table[__NR_open] = new_open;
write_cr0 (read_cr0 () | 0x10000);
return 0;
}
static void exit(void) {
write_cr0 (read_cr0 () & (~ 0x10000));
sys_call_table[__NR_open] = original_open;
write_cr0 (read_cr0 () | 0x10000);
printk(KERN_ALERT "Module unloaded\n");
return;
}
module_init(init);
module_exit(exit);
