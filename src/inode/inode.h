#ifndef INODE_H
#define INODE_H

#include <pthread.h>
#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include "memory.h"
#include <limits.h> // 包含 <limits.h> 头文件以使用 PATH_MAX

#define INODE_TABLE_SIZE 500

#define HASH_TABLE_SIZE 715

typedef struct dhmp_inode {
    char path[PATH_MAX];  //完整路径
    ino_t ino;            // inode编号
    mode_t mode;          // 文件类型和权限
    uid_t uid;            // 文件所有者
    gid_t gid;            // 文件组
    off_t size;           // 文件大小
    struct timespec atime;  // 文件访问时间
    struct timespec mtime;  // 文件修改时间
    struct timespec ctime;  // 文件状态改变时间
    nlink_t nlink;          // 链接数
    struct dhmp_block *blocks; // 指向数据块链表
    pthread_mutex_t lock;
    struct dhmp_dir *dir_entries; // 指向目录项链表的头指针
} dhmp_inode_t;

typedef struct dhmp_dir{
    char name[PATH_MAX];
    struct dhmp_inode *inode;
    struct dhmp_dir *next; //下一个目录项的指针
}dhmp_dir_t;

//哈希表中的一个桶
typedef struct hash_entry{
    char name[PATH_MAX];
    dhmp_inode_t *inode;
    struct hash_entry *next;
}hash_entry_t;

//哈希表的结构体
typedef struct hash_table{
    hash_entry_t **buckets;
    size_t bucket_count;
    pthread_mutex_t *bucket_mutexes;
}hash_table_t;

//红黑树
typedef struct rb_node {
    char name[PATH_MAX];
    dhmp_inode_t *inode;
    struct rb_node *left;
    struct rb_node *right;
    struct rb_node *parent; // 添加 parent 指针
    int color;  // 0 for black, 1 for red
} rb_node_t;

typedef struct rb_tree {
    rb_node_t *root;
    pthread_mutex_t lock;
} rb_tree_t;

typedef struct dhmp_superblock{
    struct dhmp_dir *root_directory;
    struct hash_table *hash_table; //哈希表
    rb_tree_t *rb_tree; //红黑树
}dhmp_superblock_t;

typedef struct dhmp_file_system{
    struct dhmp_superblock *sb;
}dhmp_file_system_t;

ino_t get_next_available_inode_number();
unsigned long hash_function(const char *str);
dhmp_inode_t* find_inode_by_path(hash_table_t* hash_table, const char* path);
int insert_into_hash_table(hash_table_t * hash_table,const char *path,dhmp_inode_t *inode);


void rb_insert_fixup(rb_tree_t* rb_tree, rb_node_t* node);
void rotate_left(rb_tree_t* rb_tree, rb_node_t* node);
void rotate_right(rb_tree_t* rb_tree, rb_node_t* node);

int insert_into_rb_tree(rb_tree_t* rb_tree, rb_node_t* node);
dhmp_inode_t *allocate_inode(const char *path,mode_t mode);
dhmp_file_system_t* initialize_file_system();


void print_rb_tree_helper(rb_node_t* node, int depth);

void print_rb_tree(rb_tree_t* rb_tree);

void print_hash_table(hash_table_t *hash_table);
#endif /* INODE_H */

