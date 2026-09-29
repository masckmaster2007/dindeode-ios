// darksword.h

#ifndef DARKSWORD_H
#define DARKSWORD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define EARLY_KRW_LENGTH 0x20

int go(void);
void early_kread(uint64_t where, void *read_buf, size_t size);
uint64_t early_kread64(uint64_t where);
uint64_t find_self_proc(void);
void early_kwrite64(uint64_t where, uint64_t what);
void kread_length(uint64_t address, void* buffer, uint64_t size);
void kwrite_length(uint64_t dst, void* src, uint64_t size);
void early_kwrite32bytes(uint64_t where, uint8_t writeBuf[EARLY_KRW_LENGTH]);

#ifdef __cplusplus
}
#endif

#endif