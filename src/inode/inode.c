#include "inode.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stddef.h> //包含size_t类型
#include "memory.h"

#define HASH_TABLE_SIZE 715

static pthread_mutex_t inode_number_lock = PTHREAD_MUTEX_INITIALIZER;
static ino_t current_inode_number = 1;

// 分配下一个可用的 inode_number
ino_t get_next_available_inode_number() {
    ino_t next_inode_number;

    // 加锁保证线程安全
    pthread_mutex_lock(&inode_number_lock);
    next_inode_number = ++current_inode_number;
    pthread_mutex_unlock(&inode_number_lock);

    return next_inode_number;
}


// 哈希函数，简单示例
unsigned long hash_function(const char *str) {
    unsigned long hash = 5381;
    int c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

dhmp_inode_t* find_inode_by_path(hash_table_t* hash_table, const char* path) {
    // 计算路径的哈希值，找到对应的桶
    unsigned long hash_value = hash_function(path);
    size_t bucket_index = hash_value % hash_table->bucket_count;

    // 加锁保护哈希桶
    pthread_mutex_lock(&hash_table->bucket_mutexes[bucket_index]);

    // 遍历哈希桶链表，查找对应的inode
    hash_entry_t* entry = hash_table->buckets[bucket_index];
    while (entry != NULL) {
        if (strcmp(entry->name, path) == 0) {
            pthread_mutex_unlock(&hash_table->bucket_mutexes[bucket_index]);
            return entry->inode;
        }
        entry = entry->next;
    }

    // 没找到，解锁并返回空指针
    pthread_mutex_unlock(&hash_table->bucket_mutexes[bucket_index]);
    return NULL;
}


int insert_into_hash_table(hash_table_t * hash_table,const char *path,dhmp_inode_t *inode){
    //计算路径的哈希值，可以使用简单的哈希函数
    unsigned long hash_value = hash_function(path);

    //根据哈希值计算桶的索引
    size_t bucket_index = hash_value % hash_table->bucket_count;

    //创建新的哈希表节点
    hash_entry_t *new_entry = (hash_entry_t *)malloc(sizeof(hash_entry_t));
    if(new_entry == NULL){
        fprintf(stderr,"Failed to allocate memory for hash table entry\n");
        return -ENOMEM;
    }

    //设置节点信息
    strcpy(new_entry->name,path);
    new_entry->inode = inode;
    new_entry->next = NULL;

    //加锁保护哈希桶
    pthread_mutex_lock(&hash_table->bucket_mutexes[bucket_index]);
    
    //插入节点到哈希桶链表的头部
    new_entry->next = hash_table->buckets[bucket_index];
    hash_table->buckets[bucket_index] = new_entry;

    //解锁
    pthread_mutex_unlock(&hash_table->bucket_mutexes[bucket_index]);
    return 0;

}


void rb_insert_fixup(rb_tree_t* rb_tree, rb_node_t* node);
void rotate_left(rb_tree_t* rb_tree, rb_node_t* node);
void rotate_right(rb_tree_t* rb_tree, rb_node_t* node);

int insert_into_rb_tree(rb_tree_t* rb_tree, rb_node_t* node) {
    rb_node_t* y = NULL;
    rb_node_t* x = rb_tree->root;

    while (x != NULL) {
        y = x;
        if (strcmp(node->name, x->name) < 0) {
            x = x->left;
        } else {
            x = x->right;
        }
    }

    node->parent = y;
    if (y == NULL) {
        rb_tree->root = node;  // 树为空时，新节点为根
    } else if (strcmp(node->name, y->name) < 0) {
        y->left = node;
    } else {
        y->right = node;
    }

    node->left = NULL;
    node->right = NULL;
    node->color = 1;  // 新节点为红色

    rb_insert_fixup(rb_tree, node);
    return 0;
}

void rb_insert_fixup(rb_tree_t* rb_tree, rb_node_t* node) {
    while (node != rb_tree->root && node->parent->color == 1) {
        // 父节点是祖父节点的左子节点
        if (node->parent == node->parent->parent->left) {
            rb_node_t* uncle = node->parent->parent->right;
            // Case 1: 叔叔节点是红色
            if (uncle != NULL && uncle->color == 1) {
                node->parent->color = 0;
                uncle->color = 0;
                node->parent->parent->color = 1;
                node = node->parent->parent;
            } else {
                // Case 2: 叔叔节点是黑色，且新节点是右子节点
                if (node == node->parent->right) {
                    node = node->parent;
                    rotate_left(rb_tree, node);
                }
                // Case 3: 叔叔节点是黑色，且新节点是左子节点
                node->parent->color = 0;
                node->parent->parent->color = 1;
                rotate_right(rb_tree, node->parent->parent);
            }
        }
        // 父节点是祖父节点的右子节点
        else {
            rb_node_t* uncle = node->parent->parent->left;
            // Case 1: 叔叔节点是红色
            if (uncle != NULL && uncle->color == 1) {
                node->parent->color = 0;
                uncle->color = 0;
                node->parent->parent->color = 1;
                node = node->parent->parent;
            } else {
                // Case 2: 叔叔节点是黑色，且新节点是左子节点
                if (node == node->parent->left) {
                    node = node->parent;
                    rotate_right(rb_tree, node);
                }
                // Case 3: 叔叔节点是黑色，且新节点是右子节点
                node->parent->color = 0;
                node->parent->parent->color = 1;
                rotate_left(rb_tree, node->parent->parent);
            }
        }
    }
    rb_tree->root->color = 0; // 根节点必须为黑色
}

void rotate_left(rb_tree_t* rb_tree, rb_node_t* node) {
    rb_node_t* right_child = node->right;
    node->right = right_child->left;
    if (right_child->left != NULL) {
        right_child->left->parent = node;
    }
    right_child->parent = node->parent;
    if (node->parent == NULL) {
        rb_tree->root = right_child;
    } else if (node == node->parent->left) {
        node->parent->left = right_child;
    } else {
        node->parent->right = right_child;
    }
    right_child->left = node;
    node->parent = right_child;
}

void rotate_right(rb_tree_t* rb_tree, rb_node_t* node) {
    rb_node_t* left_child = node->left;
    node->left = left_child->right;
    if (left_child->right != NULL) {
        left_child->right->parent = node;
    }
    left_child->parent = node->parent;
    if (node->parent == NULL) {
        rb_tree->root = left_child;
    } else if (node == node->parent->right) {
        node->parent->right = left_child;
    }
    left_child->right = node;
    node->parent = left_child;
}

dhmp_inode_t *allocate_inode(const char *path,mode_t mode){
    dhmp_inode_t *inode = (dhmp_inode_t *)malloc(sizeof(dhmp_inode_t));
    if(inode == NULL){
        fprintf(stderr,"Filed to allocate memory for inode\n");
        return -ENOMEM;
    }
    strncpy(inode->path,path,PATH_MAX);
    inode->path[PATH_MAX - 1] = '\0';
    inode->ino = get_next_available_inode_number();
    inode->mode = mode;
    inode->uid = getuid();
    inode->gid = getgid();
    inode->size = 0;
    inode->nlink = 2;
    clock_gettime(CLOCK_REALTIME,&inode->atime);
    inode->mtime = inode->ctime = inode->atime;
    inode->blocks = NULL;  // 可以在需要时动态分配或关联具体的数据块

    //分配数据块等其他操作
    pthread_mutex_init(&inode->lock,NULL);
    inode->dir_entries = NULL; // 初始化目录项链表为空

    return inode;
}

dhmp_file_system_t* initialize_file_system(){
    //分配文件系统全局结构体
    dhmp_file_system_t *fs = (dhmp_file_system_t *)malloc(sizeof(dhmp_file_system_t));
    if(fs==NULL){
        fprintf(stderr,"Filed to allocate memory for fs\n");
        return -ENOMEM;
    }

    //初始化超级块
    fs->sb = (dhmp_superblock_t *)malloc(sizeof(dhmp_superblock_t));
    if(fs->sb == NULL){
        fprintf(stderr,"Filed to allocate memory for sb\n");
        free(fs);
        return -ENOMEM;
    }

    //初始化根目录
    dhmp_inode_t *root_inode = allocate_inode("/",S_IFDIR | 0755);
    if (root_inode == NULL) {
        fprintf(stderr, "Failed to allocate memory for root inode\n");
        free(fs->sb);
        free(fs);
        return NULL;
    }

    //设置根目录的其他属性
    root_inode->ino = 1;
    root_inode->uid = 0;
    root_inode->gid = 0;
    root_inode->size = 0;
    clock_gettime(CLOCK_REALTIME,&root_inode->atime);
    root_inode->mtime = root_inode->ctime = root_inode->atime;
    root_inode->nlink = 2;
    root_inode->blocks = NULL;
    root_inode->dir_entries = NULL; // 初始没有目录项
    pthread_mutex_init(&root_inode->lock, NULL); // 初始化锁

    //初始化根目录
    fs->sb->root_directory = (dhmp_dir_t *)malloc(sizeof(dhmp_dir_t));
    if(fs->sb->root_directory == NULL){
        fprintf(stderr,"Filed to allocate memory for dir\n");
        free(root_inode);
        free(fs->sb);
        free(fs);
        return -ENOMEM;
    }

    strcpy(fs->sb->root_directory->name,"/");
    fs->sb->root_directory->inode = root_inode;

    //初始化哈希表
    fs->sb->hash_table = (hash_table_t *)malloc(sizeof(hash_table_t));
    if(fs->sb->hash_table == NULL){
        fprintf(stderr,"Filed to allocate memory for hash_table\n");
        free(fs->sb->root_directory);
        free(root_inode);
        free(fs->sb);
        free(fs);
        return -ENOMEM;
    }

    fs->sb->hash_table->bucket_count = HASH_TABLE_SIZE;
    fs->sb->hash_table->buckets = (hash_entry_t **)calloc(fs->sb->hash_table->bucket_count,sizeof(hash_entry_t *));

    if (fs->sb->hash_table->buckets == NULL) {
        fprintf(stderr, "Failed to allocate memory for hash buckets\n");
        free(fs->sb->hash_table);
        free(fs->sb->root_directory);
        free(root_inode);
        free(fs->sb);
        free(fs);
        return NULL;
    }

    fs->sb->hash_table->bucket_mutexes = (pthread_mutex_t *)malloc(fs->sb->hash_table->bucket_count * sizeof(pthread_mutex_t));
    if (fs->sb->hash_table->bucket_mutexes == NULL) {
        fprintf(stderr, "Failed to allocate memory for bucket mutexes\n");
        free(fs->sb->hash_table->buckets);
        free(fs->sb->hash_table);
        free(fs->sb->root_directory);
        free(root_inode);
        free(fs->sb);
        free(fs);
        return NULL;
    } 
    
    for (size_t i = 0; i < fs->sb->hash_table->bucket_count; i++) {
        pthread_mutex_init(&fs->sb->hash_table->bucket_mutexes[i], NULL);
    }
    
    //初始化红黑树
    fs->sb->rb_tree = (rb_tree_t *)malloc(sizeof(rb_tree_t));
    if(fs->sb->rb_tree == NULL){
        fprintf(stderr,"Filed to allocate memory for rb_tree\n");
        free(fs->sb->hash_table->bucket_mutexes);
        free(fs->sb->hash_table->buckets);
        free(fs->sb->hash_table);
        free(fs->sb->root_directory);
        free(root_inode);
        free(fs->sb);
        free(fs);
        return -ENOMEM;
    }

    fs->sb->rb_tree->root = NULL;
    pthread_mutex_init(&fs->sb->rb_tree->lock,NULL);

    // 插入根目录到哈希表和红黑树
    if (insert_into_hash_table(fs->sb->hash_table, "/", root_inode) != 0) {
        fprintf(stderr, "Failed to insert root inode into hash table\n");
        free(fs->sb->rb_tree);
        free(fs->sb->hash_table->bucket_mutexes);
        free(fs->sb->hash_table->buckets);
        free(fs->sb->hash_table);
        free(fs->sb->root_directory);
        free(root_inode);
        free(fs->sb);
        free(fs);
        return NULL;
    }
    rb_node_t *root_node = (rb_node_t *)malloc(sizeof(rb_node_t));
    if (root_node == NULL){
        fprintf(stderr, "Failed to allocate memory for root node\n");
        free(fs->sb->rb_tree);
        free(fs->sb->hash_table->bucket_mutexes);
        free(fs->sb->hash_table->buckets);
        free(fs->sb->hash_table);
        free(fs->sb->root_directory);
        free(root_inode);
        free(fs->sb);
        free(fs);
        return NULL;
    }

    strcpy(root_node->name,"/");
    root_node->inode = root_inode;
    root_node->left = root_node->right = NULL;
    root_node->parent = NULL;
    root_node->color = 0;//根节点为黑色
    
    if (insert_into_rb_tree(fs->sb->rb_tree, root_node) != 0) {
        fprintf(stderr, "Failed to insert root node into rb_tree\n");
        free(root_node);
        free(fs->sb->rb_tree);
        free(fs->sb->hash_table->bucket_mutexes);
        free(fs->sb->hash_table->buckets);
        free(fs->sb->hash_table);
        free(fs->sb->root_directory);
        free(root_inode);
        free(fs->sb);
        free(fs);
        return NULL;
    }
    return fs;
}

void print_rb_tree_helper(rb_node_t* node, int depth) {
    if (node == NULL) return;
    print_rb_tree_helper(node->left, depth + 1);
    for (int i = 0; i < depth; i++) {
        printf("  ");
    }
    printf("%s (%s)\n", node->name, node->color == 0 ? "black" : "red");
    print_rb_tree_helper(node->right, depth + 1);
}


void print_rb_tree(rb_tree_t* rb_tree) {
    print_rb_tree_helper(rb_tree->root, 0);
}

void print_hash_table(hash_table_t *hash_table) {
    for (size_t i = 0; i < hash_table->bucket_count; i++) {
        pthread_mutex_lock(&hash_table->bucket_mutexes[i]);
        hash_entry_t *entry = hash_table->buckets[i];
        if (entry != NULL) {
            printf("Bucket %zu:\n", i);
            while (entry != NULL) {
                printf("  - Path: %s\n", entry->name);
                entry = entry->next;
            }
        }
        pthread_mutex_unlock(&hash_table->bucket_mutexes[i]);
    }
}

