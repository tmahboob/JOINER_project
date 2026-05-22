#include "latency.h"
#include <stdio.h>
#include <time.h>

long get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000L + ts.tv_nsec;
}

void log_latency_ns(const char *context_name, long latency_ns){
    printf("[%s] Latency: %ld ns\n", context_name, latency_ns);
}