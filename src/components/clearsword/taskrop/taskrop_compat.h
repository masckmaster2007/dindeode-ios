#ifndef taskrop_compat_h
#define taskrop_compat_h

#import <stdint.h>
#import <stdbool.h>

// ---- pulls in all darksword primitives ----
#import "../krw.h"
#import "../kutils.h"
#import "../offsets.h"
#import "../xpaci.h"

// ---- rename darksword primitives to lara's ds_* names ----
#define ds_kread8(a)              kread8(a)
#define ds_kread16(a)             kread16(a)
#define ds_kread32(a)             kread32(a)
#define ds_kread64(a)             kread64(a)
#define ds_kreadbuf(a,b,c)        kreadbuf((a),(b),(c))
#define ds_kreadptr(a)            kread_ptr(a)
#define ds_kreadsmrptr(a)         kread_smrptr(a)
#define ds_kwrite8(a,v)           kwrite8((a),(v))
#define ds_kwrite16(a,v)          kwrite16((a),(v))
#define ds_kwrite32(a,v)          kwrite32((a),(v))
#define ds_kwrite64(a,v)          kwrite64((a),(v))
#define ds_kwritebuf(a,b,c)       kwritebuf((a),(b),(c))
#define ds_kwritezoneelement(a,b,c) kwrite_zone_element((a),(b),(c))
#define ds_isvalid(a)             is_kaddr_valid(a)
#define ds_kallocarrdec(a)        kalloc_array_decode(a)
#define ds_get_our_proc()         proc_self()
#define ds_get_our_task()         task_self()

// ---- lara's utils aliases ----
#define ourproc()                 proc_self()
#define procbyname(n)             proc_find_by_name(n)
#define procbypid(p)              proc_find(p)
#define taskbyproc(p)             proc_task(p)

// ---- LiveContainer: not used in your environment ----
static inline bool islcruntime(void) { return false; }

// ---- PAC support, exposed globally by darksword's offsets_init() ----
extern bool gIsPACSupported;

// TaskRop's `utils.h` and lara's `pac.m` call this; keep the same name so the
// ported sources compile unchanged.
static inline bool is_pac_supported(void) { return gIsPACSupported; }

// ---- convenience re-exports from darksword's kutils ----
// (these already exist with the same names; listed for documentation)
// uint64_t thread_get_t_tro(uint64_t thread);
// uint64_t thread_get_task(uint64_t thread);
// uint16_t thread_get_options(uint64_t thread);
// void     thread_set_options(uint64_t thread, uint16_t options);
// void     thread_set_mutex(uint64_t thread, uint32_t ctid);
// uint32_t thread_get_mutex(uint64_t thread);
// uint64_t thread_get_kstackptr(uint64_t thread);
// uint64_t thread_get_jop_pid(uint64_t thread);
// uint64_t thread_get_rop_pid(uint64_t thread);
// uint64_t proc_task(uint64_t proc);
// uint64_t task_get_ipc_port_kobject(uint64_t task, mach_port_t port);
// uint64_t task_get_vm_map(uint64_t task_ptr);
// int      disable_excguard_kill(uint64_t task);

#endif /* taskrop_compat_h */