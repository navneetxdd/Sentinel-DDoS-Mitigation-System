#ifndef SENTINEL_PLATFORM_COMPAT_H
#define SENTINEL_PLATFORM_COMPAT_H

#include <time.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#endif

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

static inline int sentinel_clock_gettime_compat(int clock_id, struct timespec *ts)
{
    if (!ts) return -1;

    if (clock_id == CLOCK_MONOTONIC) {
        static LARGE_INTEGER freq;
        static int freq_initialized = 0;
        LARGE_INTEGER counter;

        if (!freq_initialized) {
            if (!QueryPerformanceFrequency(&freq) || freq.QuadPart <= 0) {
                freq.QuadPart = 1000000;
            }
            freq_initialized = 1;
        }

        if (!QueryPerformanceCounter(&counter)) {
            return -1;
        }

        ts->tv_sec = (time_t)(counter.QuadPart / freq.QuadPart);
        ts->tv_nsec = (long)(((counter.QuadPart % freq.QuadPart) * 1000000000LL) / freq.QuadPart);
        return 0;
    }

    {
        FILETIME ft;
        ULARGE_INTEGER ticks;
        uint64_t ns_since_unix_epoch;

        GetSystemTimeAsFileTime(&ft);
        ticks.LowPart = ft.dwLowDateTime;
        ticks.HighPart = ft.dwHighDateTime;
        ns_since_unix_epoch = (uint64_t)((ticks.QuadPart - 116444736000000000ULL) * 100ULL);
        ts->tv_sec = (time_t)(ns_since_unix_epoch / 1000000000ULL);
        ts->tv_nsec = (long)(ns_since_unix_epoch % 1000000000ULL);
    }
    return 0;
}

#define clock_gettime sentinel_clock_gettime_compat
#else
#include <arpa/inet.h>
#endif

#endif /* SENTINEL_PLATFORM_COMPAT_H */
