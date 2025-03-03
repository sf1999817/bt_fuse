#ifndef MEMORY_H
#define MEMORY_H

#define DATA_BLOCK_SIZE 4096
#define INITIAL_MEMORY_POOL_SIZE (100 * 1024 * 1024) // 初始内存池大小为 100MB
#define MAX_BLOCKS (INITIAL_MEMORY_POOL_SIZE / DATA_BLOCK_SIZE) // 最大数据块数量
// 结构体定义
typedef struct dhmp_block_t {  
    char data[DATA_BLOCK_SIZE];
    int block_number;
    bool in_use;
    struct dhmp_block_t *next;
} dhmp_block_t;

typedef struct {
    dhmp_block_t blocks[MAX_BLOCKS];
    bool used[MAX_BLOCKS];      // 记录每个数据块是否被使用
    pthread_mutex_t lock;       // 用于保护内存池的互斥锁
} dhmp_memory_pool_t;

typedef struct dhmp_block{
    dhmp_block_t *block;
    struct dhmp_block *next;
}dhmp_block;

dhmp_memory_pool_t* initialize_memory_pool();

void destroy_memory_pool(dhmp_memory_pool_t* memory_pool);

dhmp_block_t* allocate_block(dhmp_memory_pool_t* memory_pool);

void free_block(dhmp_memory_pool_t* memory_pool, dhmp_block_t* block);

#endif /* MEMORY_H */
