// darksword.h

#ifndef DARKSWORD_H
#define DARKSWORD_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int go(void);
uint64_t early_kread64(uint64_t where);
uint64_t find_self_proc(void);
void early_kwrite64(uint64_t where, uint64_t what);
void kread_length(uint64_t address, void* buffer, uint64_t size);
void kwrite_length(uint64_t dst, void* src, uint64_t size);

#ifdef __cplusplus
}
#endif

#endif