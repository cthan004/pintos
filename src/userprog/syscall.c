#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <list.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

// Added System calls
void halt(void);
void exit(int status);
int exec(const char *cmd_line);
int wait(int pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

static void syscall_handler (struct intr_frame *);
static void copy_in (void *dst_, const void *usrc_, size_t size);
//static char *copy_in_string (const char *us);
static inline bool get_user (uint8_t *dst, const uint8_t *usrc);
//static bool verify_user (const void *uaddr);

struct file *get_file(int fd);

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
  if (callNum == SYS_HALT)
    numOfArgs = 0;
  else if (callNum == SYS_CREATE || callNum == SYS_SEEK)
    numOfArgs = 2;
  else if (callNum == SYS_READ || callNum == SYS_WRITE)
    numOfArgs = 3;
  else
    numOfArgs = 1;
				
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
      f->eax = exec( (const char *) args[0]);
      break;
    case SYS_WAIT:
      f->eax = wait(args[0]);
      break;
    case SYS_CREATE:
      f->eax = create( (const char *) args[0], args[1]);
      break;
    case SYS_REMOVE:
      f->eax = remove( (const char *) args[0]);
      break;
    case SYS_OPEN:
      f->eax = open( (const char *) args[0]);
      break;
    case SYS_FILESIZE:
      f->eax = filesize(args[0]);
      break;
    case SYS_READ:
      f->eax = read(args[0], (void *) args[1], args[2]);
      break;
    case SYS_WRITE:
      f->eax = write(args[0], (void *) args[1], args[2]);
      break;
    case SYS_SEEK:
      seek(args[0], args[1]);
      break;
    case SYS_TELL:
      f->eax = tell(args[0]);
      break;
    case SYS_CLOSE:
      close(args[0]);
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
  thread_exit();
}

int
exec(const char *cmd_line)
{
  return (int) process_execute(cmd_line);
}

int
wait(int pid)
{
  return process_wait(pid);
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
  struct file_st *fs = palloc_get_page(0);
  struct file *f = filesys_open(file);

  fs->f = f;

  struct thread *t = thread_current();
  if (list_empty(&t->fList))
    fs->fd = 2;
  else
  {
    int tmp_fd = list_entry(list_back(&t->fList), struct file_st, fElem)->fd;
    fs->fd = tmp_fd;
  }

  list_push_back(&t->fList, &fs->fElem);

  return fs->fd; 
}

int
filesize(int fd)
{
  struct file *f = get_file(fd);
  return file_length(f); 
}

int
read(int fd, void *buffer, unsigned size)
{
  struct file *f = get_file(fd);
  return file_read(f, buffer, size);
}

int
write(int fd, const void *buffer, unsigned size)
{
  if (fd == STDOUT_FILENO)
  {
    putbuf(buffer, size);
    return size;
  }
  struct file *f = get_file(fd);
  return file_write(f, buffer, size);
}

void
seek(int fd, unsigned position)
{ 
  struct file *f = get_file(fd);
  file_seek(f, position);
}

unsigned
tell(int fd)
{
  struct file *f = get_file(fd);
  return file_tell(f);
}

void
close(int fd)
{
  struct file *f = get_file(fd);
  file_close(f);
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
/*
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
*/

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
/*
static bool
verify_user (const void *uaddr) 
{
  return (uaddr < PHYS_BASE
    && pagedir_get_page (thread_current ()->pagedir, uaddr) != NULL);
}
*/

// This function get struct file
// given file descriptor fd
struct file *
get_file(int fd)
{
  struct thread *t = thread_current();
  struct file_st *fs;
  struct list_elem *e;
  for (e = list_begin(&t->fList);
       e != list_end(&t->fList);
       e = e->next)
  {
    fs = list_entry(e, struct file_st, fElem);
    if (fd == fs->fd)
    {
      return fs->f;
    }
  }
  
  return NULL;
}

