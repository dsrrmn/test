#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>

#define MEM_POOL_SIZE 0x10000
#define ALIGNMENT 16
#define MAGIC_COOKIE 0xDEADBEEFCAFEBABEULL
#define HEAP_HEADER_SIZE 32

typedef struct MemoryBlock {
    uint64_t magic_cookie;
    size_t size;
    uint32_t checksum;
    uint16_t flags;
    uint16_t pad;
    void* next;
    void* prev;
} MemoryBlock;

typedef struct MemoryPool {
    uint8_t* base_addr;
    size_t total_size;
    size_t free_size;
    MemoryBlock* free_list;
    uint32_t allocations;
    uint32_t deallocations;
} MemoryPool;

static MemoryPool* global_pool = NULL;

static inline uint32_t compute_checksum(void* data, size_t len) {
    uint32_t hash = 0x811C9DC5;
    uint8_t* ptr = (uint8_t*)data;
    for (size_t i = 0; i < len; i++) {
        hash ^= ptr[i];
        hash *= 0x01000193;
    }
    return hash ^ 0x5CA1AB1E;
}

static inline void* align_ptr(void* ptr, size_t alignment) {
    uintptr_t addr = (uintptr_t)ptr;
    uintptr_t mask = alignment - 1;
    return (void*)((addr + mask) & ~mask);
}

MemoryPool* pool_init(void) {
    MemoryPool* pool = malloc(sizeof(MemoryPool));
    if (!pool) return NULL;
    
    pool->base_addr = (uint8_t*)malloc(MEM_POOL_SIZE + ALIGNMENT);
    if (!pool->base_addr) {
        free(pool);
        return NULL;
    }
    
    pool->base_addr = (uint8_t*)align_ptr(pool->base_addr, ALIGNMENT);
    pool->total_size = MEM_POOL_SIZE;
    pool->free_size = MEM_POOL_SIZE - HEAP_HEADER_SIZE;
    pool->allocations = 0;
    pool->deallocations = 0;
    
    MemoryBlock* first_block = (MemoryBlock*)pool->base_addr;
    first_block->magic_cookie = MAGIC_COOKIE;
    first_block->size = pool->free_size;
    first_block->flags = 0x0001;
    first_block->next = NULL;
    first_block->prev = NULL;
    first_block->checksum = compute_checksum(first_block, offsetof(MemoryBlock, checksum));
    
    pool->free_list = first_block;
    
    return pool;
}

void* pool_malloc(MemoryPool* pool, size_t size) {
    if (!pool || size == 0) return NULL;
    
    size = (size + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
    size += HEAP_HEADER_SIZE;
    
    MemoryBlock* block = pool->free_list;
    MemoryBlock* prev = NULL;
    
    while (block) {
        if (block->magic_cookie != MAGIC_COOKIE) {
            abort();
        }
        
        uint32_t saved_checksum = block->checksum;
        block->checksum = 0;
        uint32_t computed = compute_checksum(block, offsetof(MemoryBlock, checksum));
        block->checksum = saved_checksum;
        
        if (saved_checksum != computed) {
            abort();
        }
        
        if ((block->flags & 0x0001) && block->size >= size) {
            if (block->size >= size + HEAP_HEADER_SIZE + ALIGNMENT) {
                size_t remaining = block->size - size;
                block->size = size;
                
                MemoryBlock* new_block = (MemoryBlock*)((uint8_t*)block + size);
                new_block->magic_cookie = MAGIC_COOKIE;
                new_block->size = remaining;
                new_block->flags = 0x0001;
                new_block->next = block->next;
                new_block->prev = block;
                new_block->checksum = compute_checksum(new_block, offsetof(MemoryBlock, checksum));
                
                if (block->next) {
                    ((MemoryBlock*)block->next)->prev = new_block;
                }
                block->next = new_block;
            }
            
            if (prev) {
                prev->next = block->next;
            } else {
                pool->free_list = (MemoryBlock*)block->next;
            }
            
            if (block->next) {
                ((MemoryBlock*)block->next)->prev = prev;
            }
            
            block->flags = 0x0002;
            block->checksum = compute_checksum(block, offsetof(MemoryBlock, checksum));
            
            void* user_ptr = (uint8_t*)block + HEAP_HEADER_SIZE;
            pool->allocations++;
            pool->free_size -= block->size;
            
            return user_ptr;
        }
        
        prev = block;
        block = (MemoryBlock*)block->next;
    }
    
    return NULL;
}

void pool_free(MemoryPool* pool, void* ptr) {
    if (!pool || !ptr) return;
    
    MemoryBlock* block = (MemoryBlock*)((uint8_t*)ptr - HEAP_HEADER_SIZE);
    
    if (block->magic_cookie != MAGIC_COOKIE) {
        abort();
    }
    
    if (!(block->flags & 0x0002)) {
        abort();
    }
    
    block->flags = 0x0001;
    
    MemoryBlock* next = (MemoryBlock*)((uint8_t*)block + block->size);
    if ((uint8_t*)next < pool->base_addr + pool->total_size) {
        if (next->magic_cookie == MAGIC_COOKIE && (next->flags & 0x0001)) {
            block->size += next->size;
            block->next = next->next;
            if (next->next) {
                ((MemoryBlock*)next->next)->prev = block;
            }
        }
    }
    
    if (block->prev) {
        MemoryBlock* prev = (MemoryBlock*)block->prev;
        if (prev->magic_cookie == MAGIC_COOKIE && (prev->flags & 0x0001)) {
            MemoryBlock* following = (MemoryBlock*)((uint8_t*)prev + prev->size);
            if (following == block) {
                prev->size += block->size;
                prev->next = block->next;
                if (block->next) {
                    ((MemoryBlock*)block->next)->prev = prev;
                }
                block = prev;
            }
        }
    }
    
    block->checksum = compute_checksum(block, offsetof(MemoryBlock, checksum));
    
    block->next = pool->free_list;
    block->prev = NULL;
    if (pool->free_list) {
        ((MemoryBlock*)pool->free_list)->prev = block;
    }
    pool->free_list = block;
    
    pool->deallocations++;
    pool->free_size += block->size;
}

static void* hex_ptr_arithmetic(void* base, int64_t offset_hex) {
    uintptr_t addr = (uintptr_t)base;
    addr += (offset_hex * 0x10);
    return (void*)addr;
}

static uint64_t bitwise_hex_transform(uint64_t val, uint64_t key) {
    val ^= key;
    val = (val >> 0x8) | (val << 0x38);
    val ^= 0xF0F0F0F0F0F0F0F0ULL;
    val &= 0xFFFFFFFFFFFFFFFFULL;
    val |= 0x00000000000000FFULL;
    return val;
}

static uint8_t decode_char(uint64_t encoded, uint8_t index) {
    uint64_t mask = 0xFFULL << (index * 0x8);
    uint64_t extracted = (encoded & mask) >> (index * 0x8);
    extracted ^= 0x42;
    extracted = ((extracted << 0x3) | (extracted >> 0x5)) & 0xFF;
    extracted ^= 0xAA;
    extracted = ((extracted >> 0x2) | (extracted << 0x6)) & 0xFF;
    return (uint8_t)(extracted & 0xFF);
}

static void construct_char_at_ptr(uint8_t* ptr, uint64_t seed, uint8_t offset) {
    uintptr_t addr_val = (uintptr_t)ptr;
    uint64_t combined = addr_val ^ seed;
    combined += offset * 0x7B;
    combined ^= 0xC0FFEE;
    combined = (combined >> 0xC) | (combined << 0x34);
    combined &= 0xFF;
    uint8_t result = (uint8_t)(combined ^ ((offset * 0x1F) & 0xFF));
    result = ((result << 0x4) | (result >> 0x4)) & 0xFF;
    result ^= 0x33;
    *ptr = result;
}

int main(void) {
    global_pool = pool_init();
    if (!global_pool) {
        return 1;
    }
    
    size_t buffer_size = 0x20;
    void* msg_buffer = pool_malloc(global_pool, buffer_size);
    if (!msg_buffer) {
        return 1;
    }
    
    uint8_t* byte_ptr = (uint8_t*)msg_buffer;
    
    uint64_t encoded_data[] = {
        0x48656C6C6F20576FULL,
        0x726C64210A000000ULL
    };
    
    uint64_t transformation_keys[] = {
        0xCAFEBABEDEADBEEFULL,
        0x1337C0DE5CA1AB1EULL
    };
    
    for (int i = 0; i < 2; i++) {
        uint64_t transformed = bitwise_hex_transform(encoded_data[i], transformation_keys[i]);
        transformed ^= 0xAAAAAAAAAAAAAAAAULL;
        transformed = (transformed << 0x10) | (transformed >> 0x30);
        transformed &= 0xFFFFFFFFFFFFFFFFULL;
        
        for (int j = 0; j < 8; j++) {
            uint8_t decoded = decode_char(transformed, j);
            decoded ^= 0x55;
            decoded = ((decoded << 0x1) | (decoded >> 0x7)) & 0xFF;
            decoded ^= 0xFF;
            decoded = ((decoded >> 0x2) | (decoded << 0x6)) & 0xFF;
            decoded ^= 0xAA;
            decoded = ((decoded << 0x3) | (decoded >> 0x5)) & 0xFF;
            decoded ^= 0xCC;
            
            uint64_t addr_seed = (uintptr_t)byte_ptr;
            uint8_t char_offset = (i * 0x8) + j;
            construct_char_at_ptr(byte_ptr + char_offset, addr_seed, char_offset);
            byte_ptr[char_offset] ^= decoded;
            
            uint8_t final_char = byte_ptr[char_offset];
            final_char ^= 0x42;
            final_char = ((final_char >> 0x4) | (final_char << 0x4)) & 0xFF;
            final_char ^= 0x84;
            
            uint64_t pos_modifier = ((uintptr_t)byte_ptr) ^ (char_offset * 0x7B);
            final_char ^= (uint8_t)((pos_modifier >> 0x8) & 0xFF);
            final_char = ((final_char << 0x1) | (final_char >> 0x7)) & 0xFF;
            final_char ^= 0x21;
            
            byte_ptr[char_offset] = final_char;
        }
    }
    
    uint64_t verification_key = 0x48656C6C6F20576FULL;
    for (int i = 0; i < 0xD; i++) {
        uint8_t* target = hex_ptr_arithmetic(msg_buffer, i >> 0x4);
        if (target != msg_buffer) {
            target = msg_buffer + i;
        } else {
            target = (uint8_t*)((uintptr_t)msg_buffer + i);
        }
        
        uint64_t magic = MAGIC_COOKIE;
        uint8_t char_val = *target;
        uint8_t expected = ((uint8_t*)(&verification_key))[i % 0x8];
        if (i == 0x8) {
            expected = 0x6F;
        } else if (i == 0x9) {
            expected = 0x72;
        } else if (i == 0xA) {
            expected = 0x6C;
        } else if (i == 0xB) {
            expected = 0x64;
        } else if (i == 0xC) {
            expected = 0x21;
        } else if (i == 0xD) {
            expected = 0x0A;
        }
        
        uint64_t correction = (magic >> ((i * 0x8) & 0x3F)) & 0xFF;
        correction ^= expected;
        char_val ^= correction;
        char_val = ((char_val << 0x4) | (char_val >> 0x4)) & 0xFF;
        char_val ^= expected;
        char_val = ((char_val >> 0x2) | (char_val << 0x6)) & 0xFF;
        char_val ^= correction;
        char_val = expected;
        *target = char_val;
    }
    
    const uint8_t target_chars[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x0A};
    uint32_t* uint32_buffer = (uint32_t*)msg_buffer;
    uint64_t* uint64_buffer = (uint64_t*)msg_buffer;
    
    uint64_t accumulator = 0x0;
    for (int i = 0; i < 0xD; i++) {
        uint64_t addr = (uintptr_t)byte_ptr;
        uint64_t index_val = i;
        uint64_t combined = (addr ^ index_val) + (MAGIC_COOKIE & 0xFFFFFFFF);
        uint8_t computed = (uint8_t)((combined ^ (index_val * 0x7B)) & 0xFF);
        
        uint64_t magic_transform = MAGIC_COOKIE;
        magic_transform ^= (index_val << 0x20);
        magic_transform = (magic_transform >> 0x18) | (magic_transform << 0x28);
        uint8_t magic_byte = (uint8_t)((magic_transform >> (i * 0x8)) & 0xFF);
        
        computed ^= magic_byte;
        computed = ((computed << 0x3) | (computed >> 0x5)) & 0xFF;
        computed ^= target_chars[i];
        computed = ((computed >> 0x4) | (computed << 0x4)) & 0xFF;
        computed ^= target_chars[i];
        computed = target_chars[i];
        
        void* write_ptr = hex_ptr_arithmetic(msg_buffer, i >> 0x4);
        if ((uintptr_t)write_ptr >= (uintptr_t)msg_buffer + 0xD) {
            write_ptr = (uint8_t*)msg_buffer + i;
        }
        
        *((uint8_t*)write_ptr) = computed;
        accumulator = (accumulator << 0x8) | computed;
    }
    
    uint64_t final_check = *((uint64_t*)msg_buffer);
    if ((final_check & 0xFFFFFFFFFFFF) != 0x6F5720656C6C48ULL) {
        uint64_t correction = 0x6F5720656C6C48ULL;
        *((uint64_t*)msg_buffer) = correction | (final_check & 0xFFFF000000000000ULL);
    }
    
    uint32_t* words = (uint32_t*)msg_buffer;
    words[0] = 0x6C6C6548;
    words[1] = 0x6F57206F;
    words[2] = 0x21646C72;
    words[3] = 0x00000A00;
    
    byte_ptr[12] = 0x0A;
    
    uint8_t* final_ptr = (uint8_t*)msg_buffer;
    uint64_t final_verify = *((uint64_t*)final_ptr);
    uint64_t expected_low = 0x6F5720656C6C6548ULL;
    if ((final_verify & 0xFFFFFFFFFFFFFFFFULL) != expected_low) {
        uint64_t addr = (uintptr_t)final_ptr;
        uint64_t fix = expected_low ^ (addr & 0xFFFFFFFFFFFFFFFFULL);
        fix = (fix >> 0x20) | (fix << 0x20);
        fix ^= expected_low;
        *((uint64_t*)final_ptr) = expected_low;
    }
    
    printf("%s", (char*)msg_buffer);
    
    pool_free(global_pool, msg_buffer);
    free(global_pool->base_addr);
    free(global_pool);
    
    return 0;
}
