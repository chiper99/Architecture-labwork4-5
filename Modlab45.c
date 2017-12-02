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
unsigned long *sys_call_table; //собственно адрес таблицы
asmlinkage int (*original_open)(const char*,int);
int s=0;

char *getversion(void) //узнаём версию ядра
{
   struct file *f;
   static char *fname = "/proc/version";
   static char buff[501];
   static char ver[20];
   size_t x=0,y=0;
   size_t n;
   f = filp_open(fname,O_RDONLY,0);//открываем файл
   n = kernel_read(f,0,buff,500);//читаем 500 байт в buff
   if(n){
   		buff[n]='\0';
   		while(1){  //т.к версия ядра начинается с цифры ищем первое вхождение цифры
   		if((buff[x]=='1')||(buff[x]=='2')||(buff[x]=='3')||(buff[x]=='4')||(buff[x]=='5')||(buff[x]=='6')||(buff[x]=='7')||(buff[x]=='8')||(buff[x]=='9'))break;
   		x++;
   		}
    	while(1){ //пишем в ver из buff до первого пробела
		ver[y]=buff[x];
		y++;x++;
		if(buff[x]==' ')break;
   		}
   		ver[y]='\0';//добавляем нуль терминатор
   }
   filp_close(f,NULL);
   return ver;
}

char *getpath(char *version) //функция служит только для склейки строки пути и версиии ядра
{
    static char path[100];
    strcpy(path,"/boot/System.map-");
    strcat(path,version);
    return path;
}

int getadress(char *path) //возвращает адрес, а так же присваивает его значение глобальной переменной
	                  //собсна может ничего и не возвращать
	                  //получает путь к файлу 
{
   size_t n;
   int adress;
   struct file *f;
   f = filp_open(path,O_RDONLY,0)                   //открытие файла
   int SizeBuff = vfs_llseek(f,(off_t)0,SEEK_END);  //узнаём размер файла
   char *Buff = vmalloc(SizeBuff+1);    	 		 //выделяем память под файл 
   char *str1,str2[10];                         	  //если у вас длина адреса больше чем 7-8 символов увеличивайте размер str2
   n = kernel_read(f,0,Buff,SizeBuff);           	 //читаем весь файл в буфер
   str1 = strstr(Buff,"sys_call_table\n")-11;    	 //ищем вхождение подстроки "sys_call_table\n" в буфер
   						 							 //но так как адрес находится перед этой подстрокой отнимаем от указателя 11
	                                      	  		  //так как началло адреса "отстаёт" от sys_call_table\n на 11 символов
	                                         		 //может быть подругому, проверяйте если не будет рабоать 
   strncpy(str2,str1,8);                          //опять же если длина адреса больше копируйте больше символов
   str2[8] = '\0'; 				 					 //здесь обязательо добавляем нуль терминатор
   sscanf(str2,"%lx",&sys_call_table);            //особая магия по превращению символьной строки в целое число
   return adress;
}

asmlinkage int new_open(const char *pathname, int flags)//обьявление функции которой будем подменять
{
	s++;
	if(s==30)     //так как происходит очень много перехватов выводим только каждый тридцатый
	{
		s=0;
		printk(KERN_ALERT "INTERCEPTED Path: %s",pathname);//выводим путь файла и его имя открытие которого было перехвачено
	}
	return (*original_open)(pathname, flags);//обязательно возвращаем адрес оригинального open что бы не поломать всё соовсем
}

static int init(void) {
	printk(KERN_ALERT "\nINIT\n");
	getadress(getpath(getversion())); //поиск собственно адреса таблицы прерываний
	write_cr0 (read_cr0 () & (~ 0x10000));//отключение защиты 
	original_open = (void *)sys_call_table[__NR_open];//сохраняем адрес оригинальной функции
	sys_call_table[__NR_open] = new_open;//подменяем обработчик своей функцией	
	write_cr0 (read_cr0 () | 0x10000);//включаем защиту обратно
	return 0;
}
static void exit(void) {
	write_cr0 (read_cr0 () & (~ 0x10000));//отключение защиты 
	sys_call_table[__NR_open] = original_open;//возвращаем стандартный обработчик на его законное место
	write_cr0 (read_cr0 () | 0x10000);//включаем защиту обратно
	printk(KERN_ALERT "Module unloaded\n");
	return;
}
module_init(init);
module_exit(exit);
