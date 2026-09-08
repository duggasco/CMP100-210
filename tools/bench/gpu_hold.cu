// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright 2026 duggasco
// gpu_hold.cu -- keep every block of the GPU powered and clocked for N seconds.
//
// BAR0 register reads taken through a second mapping (sysfs resource0) while RM owns the GPU
// are unreliable when the chip is idle: clock-gated partitions time out on the PRI ring and the
// read returns stale bus data rather than an error.  On this card that showed up as offset
// 0x08C040 returning 0x140000A1 -- the value of offset 0x000000.  Running a kernel that touches
// both the math pipes and framebuffer keeps the partitions awake so the reads mean something.
//
// build: nvcc -O3 -arch=sm_70 -o gpu_hold gpu_hold.cu ;  usage: gpu_hold <seconds>

#include <cstdio>
#include <cstring>
#include <cctype>
#include <cstdlib>
#include <cstdlib>
#include <cuda_runtime.h>
#define CHK(x) do { cudaError_t e_=(x); if(e_){printf("CUDA err %d: %s\n",__LINE__,cudaGetErrorString(e_));exit(1);} } while(0)

__global__ void k_hold(float4 *buf, size_t n4, long long cycles) {
    size_t i = blockIdx.x * (size_t)blockDim.x + threadIdx.x;
    size_t stride = gridDim.x * (size_t)blockDim.x;
    float acc = 1.0f;
    long long t0 = clock64();
    while (clock64() - t0 < cycles) {
        for (size_t j = i; j < n4; j += stride) {
            float4 v = buf[j];
            acc = acc * 1.000001f + v.x;
        }
    }
    if (acc == -98765.0f) buf[0].x = acc;
}


// ---- device selection ------------------------------------------------------
// ⚠ Never trust "device 0".  On a multi-GPU host the card under test is usually not device 0,
// and a clean result on the wrong GPU is worse than no result.  Pass a device index, or set
// GV100_BDF=0000:0b:00.0 to select by PCI address.  The bus id is ALWAYS printed so a
// wrong-device run is self-evident in the log.
static cudaDeviceProp pick_device(int dev)
{
    const char *want = getenv("GV100_BDF");
    if (want && *want) {
        int n = 0; CHK(cudaGetDeviceCount(&n));
        int found = -1;
        for (int i = 0; i < n; i++) {
            char id[32] = {0};
            if (cudaDeviceGetPCIBusId(id, sizeof id, i) != cudaSuccess) continue;
            // nvidia gives "00000000:0B:00.0"; accept a case-insensitive tail match on
            // "bb:dd.f" so a 4- or 8-digit domain both work.
            const char *a = id, *b = want;
            size_t la = strlen(a), lb = strlen(b);
            size_t k = la < lb ? la : lb;
            bool eq = true;
            for (size_t j = 1; j <= k; j++)
                if (tolower((unsigned char)a[la - j]) != tolower((unsigned char)b[lb - j])) { eq = false; break; }
            if (eq) { found = i; break; }
        }
        if (found < 0) {
            fprintf(stderr, "GV100_BDF=%s matched no CUDA device -- refusing to run on a "
                            "device I cannot identify\n", want);
            exit(2);
        }
        dev = found;
    }
    CHK(cudaSetDevice(dev));
    cudaDeviceProp p; CHK(cudaGetDeviceProperties(&p, dev));
    char id[32] = {0}; cudaDeviceGetPCIBusId(id, sizeof id, dev);
    printf("device %d  %s  @ %s\n", dev, p.name, id);
    return p;
}

int main(int argc, char **argv) {
    double secs = (argc > 1) ? atof(argv[1]) : 60.0;
    int dev = (argc > 2) ? atoi(argv[2]) : 0;
    cudaDeviceProp p = pick_device(dev);
    size_t bytes = 1ull << 30;
    float4 *buf; CHK(cudaMalloc(&buf, bytes)); CHK(cudaMemset(buf, 0, bytes));
    long long cycles = (long long)(secs * p.clockRate * 1000.0);
    printf("holding %s busy for ~%.0f s (%lld SM cycles)\n", p.name, secs, cycles);
    fflush(stdout);
    k_hold<<<p.multiProcessorCount * 8, 128>>>(buf, bytes / sizeof(float4), cycles);
    CHK(cudaDeviceSynchronize());
    CHK(cudaFree(buf));
    printf("done\n");
    return 0;
}
