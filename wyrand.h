//
// Created by postolka on 03.02.20.
//

#ifndef DPDK_TCP_GENERATOR_WYRAND_H
#define DPDK_TCP_GENERATOR_WYRAND_H

#include <stdint.h>

#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_config.h>

uint64_t wyrand_states[RTE_MAX_LCORE];

static inline void wyrand_seed(void)
{
    uint64_t current_tsc = rte_get_tsc_cycles();
    for (int i = 0; i < RTE_MAX_LCORE; i++) {
        wyrand_states[i] = current_tsc * (i + 1);
    }
}

// Based on https://github.com/wangyi-fudan/wyhash/blob/master/wyhash.h
static inline uint64_t wyrand_stateless(uint64_t *s)
{
    *s += UINT64_C(0xa0761d6478bd642f);
    __uint128_t t = (__uint128_t) *s * (*s ^ UINT64_C(0xe7037ed1a0b428db));
    return (t >> 64) ^ t;
}

static inline uint64_t wyrand(void)
{
    return wyrand_stateless(&wyrand_states[rte_lcore_id()]);
}

#endif //DPDK_TCP_GENERATOR_WYRAND_H
