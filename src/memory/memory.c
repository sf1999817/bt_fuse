#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <string.h>
#include <limits.h>
#include "memory.h"
#include "inode.h"
// 初始化内存池
dhmp_memory_pool_t* initialize_memory_pool() {
    dhmp_memory_pool_t* memory_pool = (dhmp_memory_pool_t *)malloc(sizeof(dhmp_memory_pool_t));
    if (memory_pool == NULL) {
        perror("Failed to allocate memory for memory pool");
        return NULL;
    }

    // 初始化数据块和使用标记
    memset(memory_pool->blocks, 0, MAX_BLOCKS * sizeof(dhmp_block_t));
    memset(memory_pool->used, 0, MAX_BLOCKS * sizeof(bool));

    // 初始化互斥锁
    if (pthread_mutex_init(&memory_pool->lock, NULL) != 0) {
        perror("Failed to initialize memory pool mutex");
        free(memory_pool);
        return NULL;
    }

    return memory_pool;
}

// 销毁内存池
void destroy_memory_pool(dhmp_memory_pool_t* memory_pool) {
    if (memory_pool == NULL) return;

    // 销毁互斥锁
    pthread_mutex_destroy(&memory_pool->lock);

    // 释放内存池结构体
    free(memory_pool);
}

// 分配数据块
dhmp_block_t* allocate_block(dhmp_memory_pool_t* memory_pool) {
    if (memory_pool == NULL) {
        return NULL;
    }

    pthread_mutex_lock(&memory_pool->lock);

    // 查找未使用的数据块
    for (size_t i = 0; i < MAX_BLOCKS; ++i) {
        if (!memory_pool->used[i]) {
            // 找到未使用的数据块，标记为已使用并返回指针
            memory_pool->used[i] = true;
            pthread_mutex_unlock(&memory_pool->lock);
            return &memory_pool->blocks[i];
        }
    }

    pthread_mutex_unlock(&memory_pool->lock);

    // 没有可用的数据块
    return NULL;
}


// 释放数据块
void free_block(dhmp_memory_pool_t* memory_pool, dhmp_block_t* block) {
    if (memory_pool == NULL || block == NULL) {
        return;
    }

    pthread_mutex_lock(&memory_pool->lock);

    // 查找数据块在数组中的索引
    size_t index = block - memory_pool->blocks;

    // 检查索引有效性
    if (index >= 0 && index < MAX_BLOCKS) {
        // 标记数据块为未使用
        memory_pool->used[index] = false;
    }

    pthread_mutex_unlock(&memory_pool->lock);
}
