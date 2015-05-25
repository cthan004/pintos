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
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/synch.h"

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
static inline bool get_user (uint8_t *dst, const uint8_t *usrc);
static bool verify_user (const void *uaddr);

static struct file_st *get_fs(int fd);

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
  //if (!is_user_vaddr(f->esp) || f->esp < (void *)CODE_SEG_BOTTOM) exit(-1);
  if (!verify_user(f->esp)) exit(-1);
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
      f->eax = create((const char *)args[0], args[1]);
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
  
  /* store exit status 
   * marked as dead in thread_exit()*/
  //if (cur->ex != NULL) cur->ex->status = status;

  if (get_thread(cur->parent)) cur->cp->status = status;

  // Close all fd in fList
  struct list_elem *e;
  while(!list_empty(&cur->fList))
  {
    e = list_begin(&cur->fList);
    close(list_entry(e, struct file_st, fElem)->fd);
  }

  // Remove all childs in cList
  struct child_st *c;
  while(!list_empty(&cur->cList))
  {
    e = list_begin(&cur->cList);
    c = list_entry(e, struct child_st, cElem);
    list_remove(&c->cElem);
    palloc_free_page(c);
  }

  thread_exit();
}

int
exec(const char *cmd_line)
{
  if (!verify_user(cmd_line))
  {
    exit(-1);
    return -1;
  }
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
  if (!verify_user(file+initial_size))
  {
    exit(-1);
    return false;
  }
  return filesys_create(file, initial_size);
}

bool
remove(const char *file)
{
  if (!verify_user(file))
  {
    exit(-1);
    return false;
  }
  return filesys_remove(file);
}

int
open(const char *file)
{
  if (!verify_user(file))
  {
    exit(-1);
    return -1;
  }
  struct file_st *fs = palloc_get_page(0);
  struct file *f = filesys_open(file);
  if (!f) return -1;

  fs->f = f;

  struct thread *t = thread_current();
  if (list_empty(&t->fList))
    fs->fd = 2;
  else
  {
    int tmp_fd = list_entry(list_back(&t->fList), struct file_st, fElem)->fd;
    fs->fd = tmp_fd+1;
  }

  list_push_back(&t->fList, &fs->fElem);

  return fs->fd; 
}

int
filesize(int fd)
{
  struct file_st *fs = get_fs(fd);
  if (!fs || !fs->f) return -1;
  return file_length(fs->f);
}

int
read(int fd, void *buffer, unsigned size)
{
  if (!verify_user(buffer+size))
  {
    exit(-1);
    return -1;
  }
  if (fd == 0)
  {
    int *tmpBuf = (int *) buffer;
    unsigned i;
    for (i = 0; i < size; ++i)
      tmpBuf[i] = input_getc();
    return size;
  }
  struct file_st *fs = get_fs(fd);
  if (!fs || !fs->f) return -1;
  return file_read(fs->f, buffer, size);
}

int
write(int fd, const void *buffer, unsigned size)
{
  if (!verify_user(buffer+size))
  {
    exit(-1);
    return -1;
  }
  if (fd == 1)
  {
    putbuf(buffer, size);
    return size;
  }
  struct file_st *fs = get_fs(fd);
  if (!fs || !fs->f) return -1;
  return file_write(fs->f, buffer, size);
}

void
seek(int fd, unsigned position)
{ 
  struct file_st *fs = get_fs(fd);
  if (fs && fs->f)
    file_seek(fs->f, position);
}

unsigned
tell(int fd)
{
  struct file_st *fs = get_fs(fd);
  if (fs && fs->f)
    return file_tell(fs->f);
  return -1;
}

void
close(int fd)
{
  struct file_st *fs = get_fs(fd);
  if (fs && fs->f)
  {
    list_remove(&fs->fElem);
    file_close(fs->f);
    palloc_free_page(fs);
  }
}


/* Copies SIZE bytes from user address USRC to kernel address
   DST.
   Call thread_exit() if any of the user accesses are invalid. */
void
copy_in (void *dst_, const void *usrc_, int size) 
{
  uint8_t *dst = dst_;
  const uint8_t *usrc = usrc_;
           
  for (; size > 0; size--, dst++, usrc++) 
    if (usrc >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc)) 
      exit(-1);
      //thread_exit ();
}

/* Creates a copy of user string US in kernel memory
   and returns it as a page that must be freed with
   palloc_free_page().
   Truncates the string at PGSIZE bytes in size.
   Call thread_exit() if any of the user accesses are invalid. */

char *
copy_in_string (const char *us) 
{
  char *ks;
  size_t length;
                       
  ks = palloc_get_page (0);
  if (ks == NULL)
    exit(-1); 
    //thread_exit ();
                                  
  for (length = 0; length < PGSIZE; length++)
  {
    if (us >= (char *) PHYS_BASE || !get_user (ks + length, us++)) 
    {
      palloc_free_page (ks);
      exit(-1);
      //thread_exit (); 
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


// This function get file struct
// given file descriptor fd
static struct file_st *
get_fs(int fd)
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
      return fs;
    }
  }
  
  return NULL;
}

