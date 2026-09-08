// gv100_memtest.cu -- full-framebuffer integrity test, for validating a memory clock change.
//
// Raising the HBM clock is the one change in this tree that can fail SILENTLY: a marginal
// interface returns wrong bits rather than hanging, and a bandwidth number looks perfect while
// the data is wrong.  So any memory-clock claim has to be backed by a written-and-verified pass
// over the whole framebuffer, not by GB/s.
//
// Four patterns, each written over the entire allocation and read back:
//   addr      value = f(address)          catches address-decode faults (wrong row/column)
//   ones      0xFFFFFFFF                  worst case for 1->0 settling
//   zeros     0x00000000                  worst case for 0->1 settling
//   random    xorshift keyed per word     uncorrelated, catches data-dependent coupling
// Verification runs in a separate kernel launch from the write so the values must have made a
// real round trip through DRAM rather than sitting in L2 (6 MiB, vs a multi-GiB allocation).
//
// build: nvcc -O3 -arch=sm_70 -o gv100_memtest gv100_memtest.cu ;  usage: gv100_memtest [GiB] [passes]

#include <cstdio>
#include <cstring>
#include <cctype>
#include <cstdlib>
#include <cstdlib>
#include <cuda_runtime.h>
#define CHK(x) do { cudaError_t e_=(x); if(e_){printf("CUDA err line %d: %s\n",__LINE__,cudaGetErrorString(e_));exit(1);} } while(0)

__device__ __forceinline__ unsigned pat(unsigned long long i, int mode, unsigned seed) {
    switch (mode) {
        case 0:  return (unsigned)(i * 2654435761u) ^ (unsigned)(i >> 32);
        case 1:  return 0xFFFFFFFFu;
        case 2:  return 0x00000000u;
        default: {
            unsigned x = (unsigned)i ^ seed; x ^= x << 13; x ^= x >> 17; x ^= x << 5; return x;
        }
    }
}

__global__ void fill(unsigned *p, unsigned long long n, int mode, unsigned seed) {
    unsigned long long i = blockIdx.x * (unsigned long long)blockDim.x + threadIdx.x;
    unsigned long long s = gridDim.x * (unsigned long long)blockDim.x;
    for (; i < n; i += s) p[i] = pat(i, mode, seed);
}

__global__ void check(const unsigned *p, unsigned long long n, int mode, unsigned seed,
                      unsigned long long *bad, unsigned long long *first) {
    unsigned long long i = blockIdx.x * (unsigned long long)blockDim.x + threadIdx.x;
    unsigned long long s = gridDim.x * (unsigned long long)blockDim.x;
    for (; i < n; i += s) {
        unsigned want = pat(i, mode, seed), got = p[i];
        if (got != want) {
            unsigned long long c = atomicAdd((unsigned long long *)bad, 1ULL);
            if (c == 0) { first[0] = i; first[1] = want; first[2] = got; }
        }
    }
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
    double gib = (argc > 1) ? atof(argv[1]) : 12.0;
    int passes = (argc > 2) ? atoi(argv[2]) : 2;
    int dev = (argc > 3) ? atoi(argv[3]) : 0;
    cudaDeviceProp p = pick_device(dev);
    size_t want_bytes = (size_t)(gib * (1ull << 30)) & ~(size_t)0xFFF;
    size_t bytes = want_bytes;
    unsigned *buf = nullptr;
    while (bytes > (1ull << 28) && cudaMalloc(&buf, bytes) != cudaSuccess) bytes -= (1ull << 28);
    if (!buf) { printf("could not allocate\n"); return 1; }
    // ⚠ The loop above backs off 256 MiB at a time until an allocation succeeds.  Report the
    // shortfall LOUDLY and fail: a "CLEAN" line covering a fraction of what was asked for is
    // how a marginal interface passes a test it never really took.
    double got_gib = bytes / 1073741824.0, want_gib = want_bytes / 1073741824.0;
    bool short_coverage = bytes < want_bytes;
    if (short_coverage)
        printf("*** COVERAGE SHORTFALL: asked for %.2f GiB, could only allocate %.2f GiB "
               "(%.0f%%). Free the GPU and re-run; this result does NOT satisfy the runbook. ***\n",
               want_gib, got_gib, 100.0 * got_gib / want_gib);
    unsigned long long n = bytes / 4;
    printf("%s  memclk %.0f MHz  testing %.2f GiB (%llu words), %d passes\n",
           p.name, p.memoryClockRate / 1000.0, bytes / 1073741824.0,
           (unsigned long long)n, passes);

    unsigned long long *dbad, *dfirst;
    CHK(cudaMalloc(&dbad, 8)); CHK(cudaMalloc(&dfirst, 24));
    int blocks = p.multiProcessorCount * 32;
    const char *names[4] = {"addr", "ones", "zeros", "random"};
    unsigned long long total = 0;

    for (int pass = 0; pass < passes; pass++) {
        for (int mode = 0; mode < 4; mode++) {
            unsigned seed = 0x9E3779B9u * (pass * 4 + mode + 1);
            CHK(cudaMemset(dbad, 0, 8));
            fill<<<blocks, 256>>>(buf, n, mode, seed);
            CHK(cudaDeviceSynchronize());
            check<<<blocks, 256>>>(buf, n, mode, seed, dbad, dfirst);
            CHK(cudaDeviceSynchronize());
            unsigned long long bad = 0, first[3] = {0, 0, 0};
            CHK(cudaMemcpy(&bad, dbad, 8, cudaMemcpyDeviceToHost));
            CHK(cudaMemcpy(first, dfirst, 24, cudaMemcpyDeviceToHost));
            total += bad;
            printf("  pass %d  %-7s  bad words %llu%s\n", pass, names[mode], bad,
                   bad ? "" : "   OK");
            if (bad)
                printf("           first at word %llu (byte 0x%llX): wanted 0x%08llX got 0x%08llX\n",
                       first[0], first[0] * 4, first[1], first[2]);
        }
    }
    printf("\n%s   total bad words: %llu over %.2f GiB x %d patterns x %d passes\n",
           total ? "*** MEMORY ERRORS ***" : "CLEAN", total,
           bytes / 1073741824.0, 4, passes);
    if (short_coverage)
        printf("*** and this run tested only %.2f of the %.2f GiB requested ***\n",
               got_gib, want_gib);
    CHK(cudaFree(buf));
    return (total || short_coverage) ? 1 : 0;
}
