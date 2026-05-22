#ifndef LATENCY_H
#define LATENCY_H

#include <stdint.h>

long get_time_ns(void);

void log_latency_ns(const char *context_name, long latency_ns);

#endif