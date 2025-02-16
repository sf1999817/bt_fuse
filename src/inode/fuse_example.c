#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <linux/futex.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <limits.h> // 包含 <limits.h> 头文件以使用 PATH_MAX
#include <stddef.h> //包含size_t类型
#include  "inode.h"
#include "memory.h"

#define SHM_NAME "/my_shared_memory"
#define SHM_SIZE 1024
#define BUFFER_SIZE 1024
#define MAX_DATA_LEN 1024

struct event {
    char pathname[256];
    int mode;
    char command[50];
    size_t size;
    char data[MAX_DATA_LEN];
};

typedef struct {
    atomic_int futex;
    char buffer[BUFFER_SIZE];
    atomic_size_t write_index;
    atomic_size_t read_index;
} shared_memory_t;

static pthread_t data_thread;  // 全局线程变量
static void *shm_ptr;
static volatile  sig_atomic_t exiting = false;
static int my_mkdir(const char *path, mode_t mode);
static int my_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
static int my_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);


FILE *log_file;
dhmp_memory_pool_t *g_memory_pool;
dhmp_file_system_t *g_fs;

dhmp_dir_t *root_directory = NULL;
hash_table_t *global_hash_table = NULL;
static shared_memory_t *shared_mem;

static int futex_wait(atomic_int *futexp, int expected, const struct timespec *timeout) {
    return syscall(SYS_futex, futexp, FUTEX_WAIT, expected, timeout, NULL, 0);
}

static int futex_wake(atomic_int *futexp, int num_wake) {
    return syscall(SYS_futex, futexp, FUTEX_WAKE, num_wake, NULL, NULL, 0);
}

void *map_shared_memory() {
    int shm_fd = shm_open(SHM_NAME, O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("shm_open failed");
        return NULL;
    }

    void *shm_ptr = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    close(shm_fd);

    if (shm_ptr == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }

    return shm_ptr;
}

void unmap_shared_memory(void *shm_ptr) {
    if (munmap(shm_ptr, SHM_SIZE) == -1) {
        perror("munmap");
    }
}

void *data_polling_thread(void *arg) {
    shared_memory_t *shared_mem = (shared_memory_t *)shm_ptr;

    struct timespec timeout;
    timeout.tv_sec = 0;  // 超时时间 1 秒
    timeout.tv_nsec = 300000000;

    while (!exiting) {
        // 等待 futex 变量变为 1，设置超时以便检查退出标志
        if (futex_wait(&shared_mem->futex, 0, &timeout) == -ETIMEDOUT) {
            if (exiting) {
                break;  // 如果接收到退出信号，退出循环
            }
            continue;  // 超时继续等待
        }

        size_t write_index = shared_mem->write_index;
        size_t read_index = shared_mem->read_index;
        size_t pos = read_index;

        fprintf(stderr, "FUSE: Reading data from shared memory: write_index = %zu, read_index = %zu\n", write_index, read_index);
        fflush(stderr);

        // 添加调试信息以确认是否进入了循环
        if (pos == write_index) {
            fprintf(stderr, "FUSE: No new data to read.\n");
            fflush(stderr);
        }

        // 读取共享内存中的数据并处理
        while (pos != write_index) {
            struct event event_in_memory;

            if (pos + sizeof(struct event) <= BUFFER_SIZE) {
                memcpy(&event_in_memory, &shared_mem->buffer[pos], sizeof(struct event));
            } else {
                size_t first_part_size = BUFFER_SIZE - pos;
                memcpy(&event_in_memory, &shared_mem->buffer[pos], first_part_size);
                memcpy((char *)&event_in_memory + first_part_size, &shared_mem->buffer[0], sizeof(struct event) - first_part_size);
            }

            // 打印解析后的数据
            fprintf(log_file,"FUSE: Event data - Pathname: %s, Mode: %o\n", event_in_memory.pathname, event_in_memory.mode);
            fflush(log_file);

            //根据event_in_memory.command决定调用哪个函数
            if(strcmp(event_in_memory.command,"mkdir") == 0){
                fprintf(log_file, "Executing mkdir for: %s\n", event_in_memory.pathname);
                fflush(log_file);
                int mkdir_result = my_mkdir(event_in_memory.pathname, event_in_memory.mode);
                fprintf(log_file, "my_mkdir returned %d\n", mkdir_result);
                fflush(log_file);
            }else if(strcmp(event_in_memory.command, "cat") == 0){
                fprintf(log_file, "Executing cat for: %s\n", event_in_memory.pathname);
                fflush(log_file);
                char read_buffer[1024];
                int read_result = my_read(event_in_memory.pathname,read_buffer,sizeof(read_buffer),0,NULL);
                fprintf(log_file, "my_read returned %d, data: %.*s\n", read_result, read_result, read_buffer);
                fflush(log_file);
            }else if(strcmp(event_in_memory.command,"echo") == 0){
                fprintf(log_file, "Executing echo for: %s\n", event_in_memory.pathname);
                fflush(log_file);
                // 实现 echo 的逻辑，例如写数据到文件
                int write_result = my_write(event_in_memory.pathname, event_in_memory.data, event_in_memory.size, 0, NULL);
                fprintf(log_file, "my_write returned %d\n", write_result);
                fflush(log_file);
            }

            pos = (pos + sizeof(struct event)) % BUFFER_SIZE;
        }

        shared_mem->read_index = pos;
        shared_mem->futex = 0;  // 重置 futex 变量
    }

    return NULL;
}

static int my_getattr(const char *path, struct stat *stbuf) {
    memset(stbuf, 0, sizeof(struct stat));

    // 在文件系统中查找对应路径的 inode 或者属性
    dhmp_inode_t *inode = find_inode_by_path(g_fs->sb->hash_table, path);
    if (inode == NULL) {
        return -ENOENT; // 文件或目录不存在
    }
    // 填充 stbuf 结构体
    stbuf->st_ino = inode->ino;          // inode 编号
    stbuf->st_mode = inode->mode;        // 文件类型和权限
    stbuf->st_nlink = inode->nlink;      // 链接数
    stbuf->st_uid = inode->uid;          // 文件所有者 ID
    stbuf->st_gid = inode->gid;          // 文件组 ID
    stbuf->st_size = inode->size;        // 文件大小
    stbuf->st_atime = inode->atime.tv_sec;  // 最后访问时间
    stbuf->st_mtime = inode->mtime.tv_sec;  // 最后修改时间
    stbuf->st_ctime = inode->ctime.tv_sec;  // 状态改变时间

    return 0;
}

static int my_create(const char *path, mode_t mode, struct fuse_file_info *fi){

    // 写入日志
    fprintf(log_file, "Path=%s, Mode=%o\n", path, mode);
    fflush(log_file);
    //分析路径，获取父目录路径和新目录名
    char parent_path[PATH_MAX];
    char dir_name[PATH_MAX];
    strncpy(parent_path,path,PATH_MAX);
    strncpy(dir_name,strrchr(path,'/')+1,PATH_MAX);
    *strrchr(parent_path,'/') = '\0';

    fprintf(log_file, "parent_path=%s, dir_name=%s\n", parent_path, dir_name);
    fflush(log_file);
    // 如果父目录路径为空，说明是根目录下创建
    if (parent_path[0] == '\0') {
        strcpy(parent_path, "/");
    }

    // 检查父目录是否存在
    dhmp_inode_t *parent_inode = find_inode_by_path(g_fs->sb->hash_table, parent_path);
    if (parent_inode == NULL) {
        return -ENOENT; // 父目录不存在
    }

    // 检查父目录是否有写权限
    if ((parent_inode->mode & S_IWUSR) == 0) {
        return -EACCES; // 没有写权限
    }

     // 分配新的 inode
    dhmp_inode_t *new_inode = allocate_inode(path, mode | S_IFREG);
    if (new_inode == NULL) {
        return -ENOMEM; // 内存分配失败
    }
    
    // 创建新的目录项节点
    dhmp_dir_t *new_dir_entry = malloc(sizeof(dhmp_dir_t));
    if (new_dir_entry == NULL) {
        free(new_inode);
        return -ENOMEM; // 内存分配失败
    }
    strncpy(new_dir_entry->name, dir_name, PATH_MAX);
    new_dir_entry->inode = new_inode;
    new_dir_entry->next = NULL;

    // 将新的目录项节点添加到父目录的链表末尾
    if (parent_inode->dir_entries == NULL) {
        parent_inode->dir_entries = new_dir_entry;
    } else {
        dhmp_dir_t *current = parent_inode->dir_entries;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = new_dir_entry;
    }

    // 更新哈希表
    if (insert_into_hash_table(g_fs->sb->hash_table, path, new_inode) != 0) {
        free(new_inode);
        return -EIO; // 插入哈希表失败
    }

    // 更新红黑树
    rb_node_t *new_node = malloc(sizeof(rb_node_t));
    if (new_node == NULL) {
        free(new_inode);
        return -ENOMEM; // 内存分配失败
    }
    strncpy(new_node->name, path, PATH_MAX);
    new_node->inode = new_inode;
    new_node->left = new_node->right = NULL;
    new_node->color = 1; // 新节点为红色
    if (insert_into_rb_tree(g_fs->sb->rb_tree, new_node) != 0) {
        free(new_inode);
        free(new_node);
        return -EIO; // 插入红黑树失败
    }

     // 写入日志或其他操作
    fprintf(log_file, "Created file: %s\n", path);
    fflush(log_file);

    // 释放资源并返回成功
    // free(new_node);
    return 0; // 成功创建文件
}

static int my_mkdir(const char *path, mode_t mode) {

    fprintf(log_file, "Path=%s, Mode=%o\n",path, mode);
    fflush(log_file);
    //分析路径，获取父目录路径和新目录名
    char parent_path[PATH_MAX];
    char dir_name[PATH_MAX];
    strncpy(parent_path,path,PATH_MAX);
    strncpy(dir_name,strrchr(path,'/')+1,PATH_MAX);
    *strrchr(parent_path,'/') = '\0';

    fprintf(log_file, "parent_path=%s, dir_name=%s\n", parent_path, dir_name);
    fflush(log_file);
    // 如果父目录路径为空，说明是根目录下创建
    if (parent_path[0] == '\0') {
        strcpy(parent_path, "/");
    }

    //查找父目录inode
    dhmp_inode_t *parent_inode = find_inode_by_path(g_fs->sb->hash_table,parent_path);
    if(parent_inode == NULL){
        return -ENOENT; //父目录不存在
    }

    fprintf(log_file, "Path=%s, Mode=%p\n", parent_inode->path, parent_inode);
    fflush(log_file);


    //检查父目录是否有写权限
    if((parent_inode->mode & S_IWUSR) == 0){
        return -EACCES;//没有写权限
    }

    //创建新的inode
    dhmp_inode_t *new_inode = allocate_inode(path,mode | S_IFDIR);
    if(new_inode == NULL){
        return -ENOMEM;//内存分配失败
    }

    // 创建新的目录项节点
    dhmp_dir_t *new_dir_entry = malloc(sizeof(dhmp_dir_t));
    if (new_dir_entry == NULL) {
        free(new_inode);
        return -ENOMEM; // 内存分配失败
    }
    strncpy(new_dir_entry->name, dir_name, PATH_MAX);
    new_dir_entry->inode = new_inode;
    new_dir_entry->next = NULL;

    // 将新的目录项节点添加到父目录的链表末尾
    if (parent_inode->dir_entries == NULL) {
        parent_inode->dir_entries = new_dir_entry;
    } else {
        dhmp_dir_t *current = parent_inode->dir_entries;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = new_dir_entry;
    }

    //更新哈希表
    if(insert_into_hash_table(g_fs->sb->hash_table,path,new_inode) != 0){
        free(new_inode);
        free(new_dir_entry);
        return -EIO; //插入哈希表失败
    }

      // 更新红黑树
    rb_node_t* new_node = malloc(sizeof(rb_node_t));
    if (new_node == NULL) {
        free(new_inode);
        free(new_dir_entry);
        return -ENOMEM; // 内存分配失败
    }
    strncpy(new_node->name, dir_name, PATH_MAX);
    new_node->inode = new_inode;
    new_node->left = new_node->right =NULL;
    new_node->color = 1; // 新节点为红色
    if (insert_into_rb_tree(g_fs->sb->rb_tree, new_node) != 0) {
        free(new_inode);
        free(new_node);
        free(new_dir_entry);
        return -EIO; // 插入红黑树失败
    }

    // 写入日志或其他操作
    fprintf(log_file, "Created directory: %s\n", path);
    fflush(log_file);

    return 0; // 成功创建目录
}

static int my_utimens(const char *path, const struct timespec tv[2]){

    // 查找文件对应的inode
    dhmp_inode_t *inode = find_inode_by_path(g_fs->sb->hash_table, path);
    if (inode == NULL) {
        return -ENOENT; // 文件不存在
    }
     // 更新访问时间和修改时间
    if (tv != NULL) {
        inode->atime = tv[0];
        inode->mtime = tv[1];
    } else {
        // 如果tv为NULL，则使用当前时间
        clock_gettime(CLOCK_REALTIME, &inode->atime);
        inode->mtime = inode->atime;
    }

    return 0; // 成功设置时间

}

static int my_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    // 写入日志
    fprintf(log_file, "Read directory: %s\n", path);
    fflush(log_file);

    // 获取文件系统的超级块
    dhmp_file_system_t *fs = g_fs;
    if (fs == NULL || fs->sb == NULL || fs->sb->hash_table == NULL) {
        fprintf(log_file, "Filesystem not properly initialized\n");
        fflush(log_file);
        return -EFAULT; // 文件系统未正确初始化
    }

    // 获取目录的 inode
    dhmp_inode_t *dir_inode = find_inode_by_path(fs->sb->hash_table, path);
    if (dir_inode == NULL) {
        fprintf(log_file, "Inode not found for path: %s\n", path);
        fflush(log_file);
        return -ENOENT; // 文件或目录不存在
    }

    // 锁定红黑树，以防止并发访问
    if (pthread_mutex_lock(&fs->sb->rb_tree->lock) != 0) {
        fprintf(log_file, "Failed to lock RB tree\n");
        fflush(log_file);
        return -EIO; // 锁定失败
    }

    // 处理 '.' 和 '..' 目录项
    if (filler(buf, ".", NULL, 0, 0) != 0) {
        pthread_mutex_unlock(&fs->sb->rb_tree->lock);
        fprintf(log_file, "Failed to fill .\n");
        fflush(log_file);
        return -ENOMEM; // 填充失败
    }

    // 添加 ".." 目录项，指向父目录（只有在根目录外的目录需要处理父目录）
    if (strcmp(path, "/") != 0) {
        // 找到父目录的路径
        char parent_path[strlen(path) + 1];
        strcpy(parent_path, path);
        char *last_slash = strrchr(parent_path, '/');
        if (last_slash != NULL && last_slash != parent_path) {
            *last_slash = '\0'; // 去掉最后的部分，得到父目录路径
        } else {
            strcpy(parent_path, "/");
        }

        // 查找父目录的 inode
        dhmp_inode_t *parent_inode = find_inode_by_path(fs->sb->hash_table, parent_path);
        if (parent_inode == NULL) {
            pthread_mutex_unlock(&fs->sb->rb_tree->lock);
            fprintf(log_file, "Parent inode not found for path: %s\n", parent_path);
            fflush(log_file);
            return -ENOENT; // 父目录不存在
        }

        if (filler(buf, "..", NULL, 0, 0) != 0) {
            pthread_mutex_unlock(&fs->sb->rb_tree->lock);
            fprintf(log_file, "Failed to fill ..\n");
            fflush(log_file);
            return -ENOMEM; // 填充失败
        }
    }

    // 遍历红黑树，将目录项填充到 buf 中
    fprintf(log_file, "Traversing RB tree\n");
    fflush(log_file);

    traverse_and_fill_rb_tree(dir_inode->dir_entries, buf, filler);

    fprintf(log_file, "Completed traversing RB tree\n");
    fflush(log_file);

    // 解锁红黑树
    if (pthread_mutex_unlock(&fs->sb->rb_tree->lock) != 0) {
        fprintf(log_file, "Failed to unlock RB tree\n");
        fflush(log_file);
        return -EIO; // 解锁失败
    }

    return 0; // 成功读取目录内容
}


void traverse_and_fill_rb_tree(rb_node_t *node, void *buf, fuse_fill_dir_t filler) {
    if (node == NULL) {
        return;
    }

    // 递归处理左子树
    traverse_and_fill_rb_tree(node->left, buf, filler);

    // 填充当前节点的名称到 buf 中
    if (filler(buf, node->name, NULL, 0, 0) != 0) {
        fprintf(log_file, "Failed to fill node: %s\n", node->name);
        fflush(log_file);
        return; // 填充失败，停止遍历
    }

    // 递归处理右子树
    traverse_and_fill_rb_tree(node->right, buf, filler);
}

// 实现 get_block_from_inode 函数
dhmp_block_t *get_block_from_inode(dhmp_inode_t *inode, size_t block_index) {
    if (inode == NULL) {
        return NULL;  // inode 为空，返回 NULL
    }

    dhmp_block *current = inode->blocks;
    while (current != NULL) {
        if (current->block->block_number == block_index) {
            pthread_mutex_unlock(&inode->lock);
            return current->block;
        }
        current = current->next;
    }
    return NULL;
}

static int my_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi){

    dhmp_file_system_t *fs = g_fs;
    if (fs == NULL || fs->sb == NULL || fs->sb->hash_table == NULL) {
        fprintf(log_file, "Filesystem not properly initialized\n");
        fflush(log_file);
        return -EFAULT; // 文件系统未正确初始化
    }

    dhmp_inode_t *inode = find_inode_by_path(fs->sb->hash_table,path);
    if(inode == NULL){
        return -ENOENT; //文件或目录不存在
    }

    fprintf(log_file, "inode->write->path:%s\n",inode->path);
    fflush(log_file);
    if(pthread_mutex_lock(&inode->lock) != 0){
        fprintf(log_file, "Failed to lock inode for path: %s\n", path);
        fflush(log_file);
        return -EIO; //锁定失败
    }

    //如果偏移量加上写入大小超过了当前文件的大小，则扩展文件
    if(offset+size > inode->size){
        size_t new_size = offset + size;
        //计算需要的块数
        size_t old_blocks = (inode->size + DATA_BLOCK_SIZE -1)/DATA_BLOCK_SIZE;
        size_t new_blocks = (new_size + DATA_BLOCK_SIZE -1)/DATA_BLOCK_SIZE;

           fprintf(log_file, "old_blocks:%d,new_blocks:%d\n",old_blocks,new_blocks);
                fflush(log_file);

        if(new_blocks > old_blocks){
            for(size_t i = old_blocks;i<new_blocks;++i){
                dhmp_block_t *block = allocate_block(g_memory_pool);
                fprintf(log_file, "inode->write->path:%p\n",block);
                fflush(log_file);
                if(block == NULL){
                    pthread_mutex_unlock(&inode->lock);
                    fprintf(log_file,"Failed to allocate block for path:%s\n",path);
                    fflush(log_file);
                    return -ENOSPC; //没有空间
                }
                   fprintf(log_file,"12345678910\n");
                fflush(log_file);
                //将新分配的块添加到文件的块链表中
                block->block_number = i; //设置块的编号
                 fprintf(log_file,"12345678910:blcok_number:%d\n",block->block_number);
                fflush(log_file);
                add_block_to_inode(inode,block);
             fprintf(log_file,"sfsfsfsfsfs\n");
                fflush(log_file);
            }
        }
        //更新文件大小
        inode->size = new_size;
    }

    //计算块偏移量和索引
    size_t block_offset = offset % DATA_BLOCK_SIZE;
    size_t block_index = offset / DATA_BLOCK_SIZE;

    //将数据写入数据块
    size_t bytes_written = 0;
    while(bytes_written < size){
        //查找当前块
        dhmp_block_t *block = get_block_from_inode(inode,block_index);
           fprintf(log_file,"nihao xiyaou 123456\n");
                fflush(log_file);
        if(block == NULL){
            pthread_mutex_unlock(&inode->lock);
            fprintf(log_file, "Failed to get block from inode for path: %s\n", path);
            fflush(log_file);
            return -EIO;
        }


        fprintf(log_file, "11111111111111111111\n");
            fflush(log_file);
        //计算要写入的数据长度
        size_t to_write = DATA_BLOCK_SIZE - block_offset < size - bytes_written ? DATA_BLOCK_SIZE - block_offset : size -bytes_written;
         fprintf(log_file, "33333333333333333333333333333333333\n");
            fflush(log_file);
        memcpy(block->data + block_offset,buf + bytes_written,to_write);
 fprintf(log_file, "222222222222222222222222\n");
            fflush(log_file);
        bytes_written += to_write;
        block_offset = 0; //后续块从起始位置写入
        block_index++; //移动到下一个块
    }

    //更新inode的修改事件和状态更改时间
    clock_gettime(CLOCK_REALTIME,&inode->mtime);
    inode->ctime = inode->mtime;

    //解锁inode
    if(pthread_mutex_unlock(&inode->lock) != 0){
        fprintf(log_file,"Failed to unlock indoe for path:%s\n",path);
        fflush(log_file);
        return -EIO;
    }

    return size; //返回写入的字节数
}

void add_block_to_inode(dhmp_inode_t *inode, dhmp_block_t *block) {
    if (inode == NULL || block == NULL) {
        fprintf(log_file, "Error: inode or block is NULL\n");
        fflush(log_file);
        return;
    }

    block->in_use = true;

    // 检查是否已存在相同的块
    dhmp_block *current = inode->blocks;
    while (current != NULL) {
        if (current->block->block_number == block->block_number) {
            fprintf(log_file, "Block already exists\n");
            fflush(log_file);
            return;
        }
        current = current->next;
    }

    // 创建新的块节点
    dhmp_block *new_block_node = malloc(sizeof(dhmp_block));
    if (new_block_node == NULL) {
        fprintf(log_file, "Error: malloc failed\n");
        fflush(log_file);
        return;
    }

    // 初始化新的块节点
    new_block_node->block = block;
    new_block_node->next = inode->blocks;
    inode->blocks = new_block_node;

    fprintf(log_file, "Block added successfully\n");
    fflush(log_file);
}

static int my_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
     fprintf(log_file, "path:%s\n",path);
    fflush(log_file);
    dhmp_file_system_t *fs = g_fs;
    if (fs == NULL || fs->sb == NULL || fs->sb->hash_table == NULL) {
        fprintf(log_file, "Filesystem not properly initialized\n");
        fflush(log_file);
        return -EFAULT; // 文件系统未正确初始化
    }

    //查找inode
    dhmp_inode_t *inode = find_inode_by_path(fs->sb->hash_table,path);

    if(inode == NULL){
        return -ENOENT; //文件或目录不存在
    }

    if(pthread_mutex_lock(&inode->lock) != 0){
        fprintf(log_file, "Failed to lock inode for path: %s\n", path);
        fflush(log_file);
        return -EIO; // 锁定失败
    }

    //检查读取偏移量是否超出文件大小
    if(offset >= inode->size){
        pthread_mutex_unlock(&inode->lock);
        return 0; //偏移量超出文件大小，返回0表示EFO
    }

    //计算实际读取的大小
    if(offset + size > inode->size){
        size = inode->size - offset;
    }

    //计算块偏移量和索引
    size_t block_offset = offset % DATA_BLOCK_SIZE;
    size_t block_index = offset / DATA_BLOCK_SIZE;

    //从数据块中读取数据
    size_t bytes_read = 0;
    while(bytes_read < size){
        //查找当前块
        dhmp_block_t *block = get_block_from_inode(inode,block_index);
        if(block == NULL){
            pthread_mutex_unlock(&inode->lock);
            fprintf(log_file, "Failed to get block from inode for path: %s\n", path);
            fflush(log_file);
            return -EIO;
        }
        //计算要读取的数据长度
        size_t to_read = DATA_BLOCK_SIZE - block_offset < size - bytes_read ? DATA_BLOCK_SIZE - block_offset : size - bytes_read;
        memcpy(buf+bytes_read,block->data+block_offset,to_read);

        bytes_read += to_read;
        block_offset = 0; //后续块从起始位置读取
        block_index++; //移动到下一块
    }

    if(pthread_mutex_unlock(&inode->lock) != 0){
        fprintf(log_file, "Failed to unlock inode for path: %s\n", path);
        fflush(log_file);
        return -EIO;
    }
    return bytes_read;
}


static void *my_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
    (void) conn;
    (void) cfg;

    shm_ptr = map_shared_memory();
    if (!shm_ptr) {
        fprintf(log_file, "Failed to map shared memory\n");
        fflush(log_file);
        return NULL;
    }

    shared_mem = (shared_memory_t *)shm_ptr;

    if (pthread_create(&data_thread, NULL, data_polling_thread, NULL) != 0) {
        perror("pthread_create failed");
        unmap_shared_memory(shm_ptr);
        return NULL;
    }

    return NULL;
}

static void my_destroy(void *userdata) {
    (void)userdata;
    exiting = true;
    pthread_join(data_thread, NULL);
    unmap_shared_memory(shm_ptr);
}

static struct fuse_operations my_ops = {
    .getattr = my_getattr,
    .read = my_read,
    .write = my_write,
    .create = my_create,
    .utimens = my_utimens,
    .readdir = my_readdir,
    .mkdir = my_mkdir,
    .init = my_init,
    .destroy = my_destroy,
};


int main(int argc, char *argv[]) {

    log_file = fopen("fuse_log.txt", "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        return EXIT_FAILURE;
    }
  
    //初始化内存池
    g_memory_pool = initialize_memory_pool();

    printf("g_memoru_pool:%p\n",g_memory_pool);

    // 初始化文件系统
    g_fs = initialize_file_system();
    printf("g_memoru_pool:%p\n",g_fs);
    printf("123path:%s\n",g_fs->sb->root_directory->inode->path);

    // 启动文件系统
    int ret = fuse_main(argc, argv, &my_ops, NULL);
     if (ret != 0) {
        fprintf(stderr, "fuse_main failed with return code %d\n", ret);
    }
    // 关闭日志文件
    fclose(log_file);
    return 0;
}
