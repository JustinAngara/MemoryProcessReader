//
// Created by justi on 6/21/2025.
//

#ifndef TEST_H
#define TEST_H
#include <stdint.h>

int run();
typedef struct {
    uintptr_t mem_ptr;
    uintptr_t mem_size;
    char mem_state[16];
    char mem_type[16];
    char mem_protection[16];
} process_data;
#endif //TEST_H
