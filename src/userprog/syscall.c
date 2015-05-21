#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);
static void copy_in (void *dst_, const void *usrc_, size_t size);
static char *copy_in_string (const char *us);
static inline bool get_user (uint8_t *dst, const uint8_t *usrc);
static bool verify_user (const void *uaddr);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
  unsigned callNum;
  int args[3];
  int numOfArgs;
	
  //##Get syscall number
  copy_in (&callNum, f->esp, sizeof callNum);

  //##Using the number find out which system call is being used
  //numOfArgs = number of args that system call uses {0,1,2,3}
  numOfArgs = 3;
				
  copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * numOfArgs);
					
  //##Use switch statement or something and run this below for each
  //##Depending on the callNum...
  //f->eax = desired_sys_call_fun (args[0], args[1], args[2]);
  switch (callNum)
  {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      exit(args[0]);
      break;
    case SYS_EXEC:
      break;
    case SYS_WAIT:
      break;
    case SYS_CREATE:
      break;
    case SYS_REMOVE:
      break;
    case SYS_OPEN:
      break;
    case SYS_FILESIZE:
      break;
    case SYS_READ:
      break;
    case SYS_WRITE:
      //f->eax = write();
      break;
    case SYS_SEEK:
      break;
    case SYS_TELL:
      break;
    case SYS_CLOSE:
      break;
    default:
      break;
  }
}

void
halt()
{
  shutdown_power_off();
}

void
exit(int status)
{
  struct thread *cur = thread_current();
  printf("%s: exit(%d)\n", cur->name, status);
}

int
exec(const char *cmd_line)
{
  return process_execute(cmd_line);
}

int
wait(int pid)
{
  return process_wait();
}

bool
create(const char *file, unsigned initial_size)
{
  return filesys_create(file, initial_size);
}

bool
remove(const char *file)
{
  return filesys_remove(file);
}

int
open(const char *file)
{
  
}

int
filesize(int fd)
{
  
}

int
read(int fd, void *buffer, unsigned size)
{
  
}

int
write(int fd, const void *buffer, unsigned size)
{
  if (fd == STDOUT_FILENO)
  {
    putbuf(buffer, size);
    return size;
  }
}

void
seek(int fd, unsigned position)
{
//
}

unsigned
tell(int fd)
{

}

void
close(int fd)
{

}


/* Copies SIZE bytes from user address USRC to kernel address
   DST.
   Call thread_exit() if any of the user accesses are invalid. */
static void
copy_in (void *dst_, const void *usrc_, size_t size) 
{
  uint8_t *dst = dst_;
  const uint8_t *usrc = usrc_;
           
  for (; size > 0; size--, dst++, usrc++) 
    if (usrc >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc)) 
      thread_exit ();
}

/* Creates a copy of user string US in kernel memory
   and returns it as a page that must be freed with
   palloc_free_page().
   Truncates the string at PGSIZE bytes in size.
   Call thread_exit() if any of the user accesses are invalid. */
static char *
copy_in_string (const char *us) 
{
  char *ks;
  size_t length;
                       
  ks = palloc_get_page (0);
  if (ks == NULL) 
    thread_exit ();
                                  
  for (length = 0; length < PGSIZE; length++)
  {
    if (us >= (char *) PHYS_BASE || !get_user (ks + length, us++)) 
    {
      palloc_free_page (ks);
      thread_exit (); 
    }
    if (ks[length] == '\0') 
      return ks;
  }
  ks[PGSIZE - 1] = '\0';
  return ks;
}

/* Copies a byte from user address USRC to kernel address DST.
   USRC must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
get_user (uint8_t *dst, const uint8_t *usrc)
{
  int eax;
  asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
    : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
  return eax != 0;
}

/* Returns true if UADDR is a valid, mapped user address,
   false otherwise. */
static bool
verify_user (const void *uaddr) 
{
  return (uaddr < PHYS_BASE
    && pagedir_get_page (thread_current ()->pagedir, uaddr) != NULL);
}
	
