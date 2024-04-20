// based on cs3650 starter code

#include <assert.h>
#include <bsd/string.h>
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_FILES 100
#define BLOCK_SIZE 4096
#define FS_SIZE (1024 * 1024) // 1MB
#define MAX_FILENAME 255
#define MAX_BLOCKS_PER_FILE 128 // This allows for a maximum file size of 512KB

#define FUSE_USE_VERSION 26
#include <fuse.h>

char *global_data_file_path;

// Struct to hold file metadata
typedef struct {
  char name[MAX_FILENAME + 1];
  int size;
  int blocks[MAX_BLOCKS_PER_FILE];
  int block_count;
  int is_directory;
  int used;
} file_meta_t;

// Struct to represent the entire filesystem
typedef struct {
  file_meta_t files[MAX_FILES];
  char data[FS_SIZE];
  unsigned char block_bitmap[FS_SIZE / BLOCK_SIZE];
} my_filesystem;

my_filesystem fs;

// Min method to return the min from two ints
static inline int min(int a, int b) { return (a < b) ? a : b; }

void write_fs_state() {
  // open and reading files
  FILE *file = fopen(global_data_file_path, "r+b");
  if (file) {
    if (fwrite(&fs, sizeof(my_filesystem), 1, file) != 1) {
      fprintf(stderr, "Error: Unable to write filesystem state to %s\n",
              global_data_file_path);
    }
    fclose(file);
  } else {
    fprintf(stderr, "Error: Unable to open filesystem file %s for writing\n",
            global_data_file_path);
  }
}

// Function to initialize the filesystem
void fs_init(const char *data_file) {
  FILE *file = fopen(data_file, "r+b"); // reads and writes
  if (file) {
    // File exists
    if (fread(&fs, sizeof(my_filesystem), 1, file) != 1) {
      fprintf(stderr, "Error: Unable to read filesystem state from %s\n",
              data_file);
      fclose(file);
      exit(1);
    }
    fclose(file);
  } else {
    // File does not exist
    memset(&fs, 0, sizeof(fs));
    fs.files[0].used = 1;
    fs.files[0].is_directory = 1;
    strcpy(fs.files[0].name, "/");
    fs.block_bitmap[0] = 1;

    file = fopen(data_file, "w+b"); // writing and reading
    if (!file) {
      fprintf(stderr, "Error: Unable to create filesystem file %s\n",
              data_file);
      exit(1);
    }
    if (fwrite(&fs, sizeof(my_filesystem), 1, file) != 1) {
      fprintf(stderr, "Error: Unable to write initial filesystem state to %s\n",
              data_file);
      fclose(file);
      exit(1);
    }
    fclose(file);
  }
}

// Function to find a free block in the filesystem
int find_free_block() {
  for (int i = 0; i < FS_SIZE / BLOCK_SIZE; i++) {
    if (!fs.block_bitmap[i]) {
      // marks block as used
      fs.block_bitmap[i] = 1;
      return i;
    }
  }
  // no free block
  return -1;
}

// Function to find a free slot for a new file in the filesystem
int find_free_file_slot() {
  for (int i = 0; i < MAX_FILES; i++) {
    if (!fs.files[i].used) {
      return i;
    }
  }
  // no free file
  return -1;
}

// Function to allocate blocks for a file
int allocate_blocks(int blocks_needed, int blocks[]) {
  int blocks_allocated = 0;
  for (int i = 0; i < FS_SIZE / BLOCK_SIZE && blocks_allocated < blocks_needed;
       i++) {
    if (!fs.block_bitmap[i]) {
      // block is used
      fs.block_bitmap[i] = 1;
      blocks[blocks_allocated++] = i;
    }
  }
  return blocks_allocated == blocks_needed ? 0 : -ENOSPC;
}

// free blocks used by a file
void free_blocks(int blocks[], int block_count) {
  for (int i = 0; i < block_count; i++) {
    fs.block_bitmap[blocks[i]] = 0;
  }
}
// adjust the size of a file
int adjust_file_size(file_meta_t *meta, int new_size) {
  int new_block_count = (new_size + BLOCK_SIZE - 1) / BLOCK_SIZE;

  if (new_block_count > meta->block_count) {
    int additional_blocks_needed = new_block_count - meta->block_count;
    int alloc_result = allocate_blocks(additional_blocks_needed,
                                       &meta->blocks[meta->block_count]);
    if (alloc_result != 0) {
      return alloc_result;
    }
    meta->block_count = new_block_count;
  } else if (new_block_count < meta->block_count) {
    free_blocks(&meta->blocks[new_block_count],
                meta->block_count - new_block_count);
    meta->block_count = new_block_count;
  }

  meta->size = new_size;
  return 0;
}
// checks if a directory is empty
bool is_directory_empty(const file_meta_t *dir) {
  char prefix[MAX_FILENAME + 2];
  snprintf(prefix, sizeof(prefix), "%s/", dir->name);

  for (int i = 0; i < MAX_FILES; i++) {
    if (fs.files[i].used &&
        strncmp(fs.files[i].name, prefix, strlen(prefix)) == 0) {
      return false;
    }
  }
  return true;
}

// fuction to update a directory, added for the sake of wanting to improving
// this later on
void update_directory_contents(const char *path, bool removed) {
  // stub
}

// implementation for: man 2 access
// Checks if a file exists.
int nufs_access(const char *path, int mask) {
  printf("access(%s, %04o)\n", path, mask);

  if (strcmp(path, "/") == 0) {
    return 0; // root directory exits
  }
  for (int i = 0; i < MAX_FILES; i++) {
    if (fs.files[i].used && strcmp(fs.files[i].name, path) == 0) {
      return 0;
    }
  }

  return -ENOENT;
}

// Gets an object's attributes (type, permissions, size, etc).
// Implementation for: man 2 stat
int nufs_getattr(const char *path, struct stat *st) {
  int rv = -ENOENT;

  memset(st, 0, sizeof(struct stat));
  if (strcmp(path, "/") == 0) {
    st->st_mode = 040755; // Directory with rwxr-xr-x permissions
    st->st_nlink = 2;
    rv = 0;
  } else {
    for (int i = 0; i < MAX_FILES; i++) {
      if (fs.files[i].used && strcmp(fs.files[i].name, path) == 0) {
        st->st_mode = fs.files[i].is_directory ? (040755) : (0100644);
        st->st_nlink = 1; // Standard for files
        st->st_size = fs.files[i].size;
        rv = 0;
        break;
      }
    }
  }

  printf("getattr(%s) -> (%d) {mode: %04o, size: %ld}\n", path, rv, st->st_mode,
         st->st_size);
  return rv;
}

// implementation for: man 2 readdir
// lists the contents of a directory

int nufs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                 off_t offset, struct fuse_file_info *fi) {
  struct stat st;
  int rv = 0;

  rv = nufs_getattr("/", &st);
  assert(rv == 0);

  filler(buf, ".", &st, 0);
  filler(buf, "..", &st, 0);

  for (int i = 0; i < MAX_FILES; i++) {
    if (fs.files[i].used) {
      rv = nufs_getattr(fs.files[i].name, &st);
      assert(rv == 0);
      filler(buf, fs.files[i].name + 1, &st, 0); // +1 to skip leading '/'
    }
  }

  printf("readdir(%s) -> %d\n", path, rv);
  return 0;
}

// mknod makes a filesystem object like a file or directory
// called for: man 2 open, man 2 link
// Note, for this assignment, you can alternatively implement the create
// function.
int nufs_mknod(const char *path, mode_t mode, dev_t rdev) {
  if (strlen(path) > MAX_FILENAME || path[0] != '/') {
    return -ENAMETOOLONG;
  }

  int slot = find_free_file_slot();
  if (slot < 0) {
    return -ENOSPC;
  }

  file_meta_t *meta = &fs.files[slot];
  meta->used = 1;
  meta->size = 0;
  meta->block_count = 0;
  meta->is_directory = S_ISDIR(mode);
  strncpy(meta->name, path, MAX_FILENAME);
  meta->name[MAX_FILENAME] = '\0';

  if (!meta->is_directory) {
    int blocks_needed = 1;
    int alloc_result = allocate_blocks(blocks_needed, meta->blocks);
    if (alloc_result != 0) {
      meta->used = 0;
      return alloc_result;
    }
    meta->block_count = blocks_needed;
  }
  write_fs_state();
  return 0;
}

// most of the following callbacks implement
// another system call; see section 2 of the manual
int nufs_mkdir(const char *path, mode_t mode) {
  int rv = nufs_mknod(path, mode | 040000, 0);
  printf("mkdir(%s) -> %d\n", path, rv);
  return rv;
}

// unlink removes a file
int nufs_unlink(const char *path) {
  if (strlen(path) > MAX_FILENAME || path[0] != '/') {
    return -ENAMETOOLONG;
  }

  for (int i = 0; i < MAX_FILES; i++) {
    if (fs.files[i].used && strcmp(fs.files[i].name, path) == 0) {
      if (fs.files[i].is_directory) {
        if (!is_directory_empty(&fs.files[i])) {
          return -ENOTEMPTY;
        }
      }

      free_blocks(fs.files[i].blocks, fs.files[i].block_count);
      memset(&fs.files[i], 0, sizeof(file_meta_t));
      update_directory_contents(path, false);

      write_fs_state(); // Save the filesystem state after unlinking
      return 0;
    }
  }
  return -ENOENT;
}

int nufs_link(const char *from, const char *to) {
  int rv = -1;
  printf("link(%s => %s) -> %d\n", from, to, rv);
  return rv;
}

int nufs_rmdir(const char *path) {
  int rv = -1;
  printf("rmdir(%s) -> %d\n", path, rv);
  return rv;
}

// implements: man 2 rename
// called to move a file within the same filesystem
int nufs_rename(const char *from, const char *to) {
  for (int i = 0; i < MAX_FILES; i++) {
    if (fs.files[i].used && strcmp(fs.files[i].name, from) == 0) {
      strncpy(fs.files[i].name, to, MAX_FILENAME);
      fs.files[i].name[MAX_FILENAME] = '\0';
      return 0;
    }
  }
  return -ENOENT;
}

int nufs_chmod(const char *path, mode_t mode) {
  int rv = -1;
  printf("chmod(%s, %04o) -> %d\n", path, mode, rv);
  return rv;
}

int nufs_truncate(const char *path, off_t size) {
  int rv = -1;
  printf("truncate(%s, %ld bytes) -> %d\n", path, size, rv);
  return rv;
}

// This is called on open, but doesn't need to do much
// since FUSE doesn't assume you maintain state for
// open files.
// You can just check whether the file is accessible.
int nufs_open(const char *path, struct fuse_file_info *fi) {
  int rv = 0;
  printf("open(%s) -> %d\n", path, rv);
  return rv;
}

// Actually read data
int nufs_read(const char *path, char *buf, size_t size, off_t offset,
              struct fuse_file_info *fi) {
  for (int i = 0; i < MAX_FILES; i++) {
    if (fs.files[i].used && strcmp(fs.files[i].name, path) == 0) {
      file_meta_t *meta = &fs.files[i];
      if (offset >= meta->size) {
        return 0;
      }
      if (offset + size > meta->size) {
        size = meta->size - offset;
      }

      int block_index = offset / BLOCK_SIZE;
      int block_offset = offset % BLOCK_SIZE;
      int bytes_read = 0;

      while (bytes_read < size && block_index < meta->block_count) {
        int block = meta->blocks[block_index];
        int bytes_to_read = min(size - bytes_read, BLOCK_SIZE - block_offset);
        memcpy(buf + bytes_read, fs.data + block * BLOCK_SIZE + block_offset,
               bytes_to_read);
        bytes_read += bytes_to_read;
        block_index++;
        block_offset = 0;
      }

      return bytes_read;
    }
  }
  return -ENOENT;
}

// Actually write data
int nufs_write(const char *path, const char *buf, size_t size, off_t offset,
               struct fuse_file_info *fi) {
  for (int i = 0; i < MAX_FILES; i++) {
    if (fs.files[i].used && strcmp(fs.files[i].name, path) == 0) {
      file_meta_t *meta = &fs.files[i];
      int end_of_write = offset + size;
      if (end_of_write > meta->size) {
        int resize_result = adjust_file_size(meta, end_of_write);
        if (resize_result != 0) {
          return resize_result;
        }
      }

      int block_index = offset / BLOCK_SIZE;
      int block_offset = offset % BLOCK_SIZE;
      int bytes_written = 0;

      while (bytes_written < size && block_index < meta->block_count) {
        int block = meta->blocks[block_index];
        int bytes_to_write =
            min(size - bytes_written, BLOCK_SIZE - block_offset);
        memcpy(fs.data + block * BLOCK_SIZE + block_offset, buf + bytes_written,
               bytes_to_write);
        bytes_written += bytes_to_write;
        block_index++;
        block_offset = 0;
      }

      write_fs_state();
      return bytes_written;
    }
  }
  return -ENOENT;
}

// Update the timestamps on a file or directory.
int nufs_utimens(const char *path, const struct timespec ts[2]) {
  int rv = -1;
  printf("utimens(%s, [%ld, %ld; %ld %ld]) -> %d\n", path, ts[0].tv_sec,
         ts[0].tv_nsec, ts[1].tv_sec, ts[1].tv_nsec, rv);
  return rv;
}

// Extended operations
int nufs_ioctl(const char *path, int cmd, void *arg, struct fuse_file_info *fi,
               unsigned int flags, void *data) {
  int rv = -1;
  printf("ioctl(%s, %d, ...) -> %d\n", path, cmd, rv);
  return rv;
}

void nufs_init_ops(struct fuse_operations *ops) {
  memset(ops, 0, sizeof(struct fuse_operations));
  ops->access = nufs_access;
  ops->getattr = nufs_getattr;
  ops->readdir = nufs_readdir;
  ops->mknod = nufs_mknod;
  // ops->create   = nufs_create; // alternative to mknod
  ops->mkdir = nufs_mkdir;
  ops->link = nufs_link;
  ops->unlink = nufs_unlink;
  ops->rmdir = nufs_rmdir;
  ops->rename = nufs_rename;
  ops->chmod = nufs_chmod;
  ops->truncate = nufs_truncate;
  ops->open = nufs_open;
  ops->read = nufs_read;
  ops->write = nufs_write;
  ops->utimens = nufs_utimens;
  ops->ioctl = nufs_ioctl;
};

// Mount the filesystem
void storage_init(const char *path) {
  FILE *file =
      fopen(path, "r+b"); // Try opening the file for reading and writing

  if (file) {
    // File exists, load the filesystem state
    if (fread(&fs, sizeof(my_filesystem), 1, file) != 1) {
      perror("Failed to read existing filesystem");
      fclose(file);
      exit(EXIT_FAILURE);
    }
    fclose(file);
  } else {
    // File does not exist
    memset(&fs, 0, sizeof(my_filesystem));

    // Save the new filesystem state to the file
    file = fopen(path, "w+b");
    if (!file || fwrite(&fs, sizeof(my_filesystem), 1, file) != 1) {
      perror("Failed to create new filesystem");
      if (file) {
        fclose(file);
      }
      exit(EXIT_FAILURE);
    }
    fclose(file);
  }
}

struct fuse_operations nufs_ops;

int main(int argc, char *argv[]) {
  if (argc < 4) {
    fprintf(stderr, "Usage: %s [FUSE options] <mountpoint> <datafile>\n",
            argv[0]);
    return 1;
  }

  // the last argument is the path to the data file
  char *data_file = argv[argc - 1];
  global_data_file_path = argv[argc - 1];

  // initialize filesystem storage
  storage_init(data_file);
  printf("Mounted %s as data file\n", data_file);

  // remove the last argument
  argc--;

  nufs_init_ops(&nufs_ops);
  return fuse_main(argc, argv, &nufs_ops, NULL);
}

