#pragma once
#include <stdint.h>

/// Attempts to self-enable JIT using DarkSword kernel R/W.
/// Returns 0 on success, errno-style code on failure.
int enable_self_jit(void);