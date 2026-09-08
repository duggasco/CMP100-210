// gv100_pipes.cu -- issue-rate and bandwidth microbenchmarks for a Volta GV100.
//
// Purpose: the CMP 100-210's devinit writes 0x999 to FECS_FEATURE_OVERRIDE_SM_SPEED_SELECT,
// putting IMLA (int), FMLA (fp32) and DP (fp64) into REDUCED_SPEED; once the card is POSTed,
// FECS_FEATURE_READOUT bits 20/21/22 confirm all three latched reduced.  This measures what
// that costs, against the architectural peak for compute capability 7.0:
//
//     per SM per clock (FMA ops):  FP32 64   FP64 32   INT32 IMAD 64   FP16x2 128   HMMA 512
//
// Each test keeps UNROLL independent dependency chains so the pipe, not latency, is the limit.
// UNROLL and occupancy are tuned PER TYPE: a double needs two registers, so the fp32 settings
// spill the register file for fp64 and the kernel becomes local-memory bound rather than
// pipe bound (that mistake reads as a ~22x fp64 deficit that is not there).  Build with
// -Xptxas -v and check "0 bytes spill" before believing any number here.
//
// The reported clock is measured on block 0 as clock64()/wall.  It is only meaningful when
// every block is resident at once; if occupancy is below the launch size it reads low by
// exactly the ratio, which is itself the tell for a spill.  Percentages are computed against
// the peak at the LOCKED clock (nvidia-smi -lgc), not against the measured one.
//
// build: nvcc -O3 -arch=sm_70 --extended-lambda -Xptxas -v -o gv100_pipes gv100_pipes.cu

#include <cstdio>
#include <cstring>
#include <cctype>
#include <cstdlib>
#include <cuda_runtime.h>
#include <mma.h>

#define CHK(x) do { cudaError_t e_ = (x); if (e_ != cudaSuccess) { \
    printf("CUDA error %s at line %d: %s\n", #x, __LINE__, cudaGetErrorString(e_)); \
    exit(1); } } while (0)

// ---------------------------------------------------------------- compute pipes

template <typename T, int UNROLL>
__global__ __launch_bounds__(128) void k_fma(T *out, T a, T b, int iters, long long *clk) {
    T x[UNROLL];
#pragma unroll
    for (int i = 0; i < UNROLL; i++) x[i] = a + (T)i;
    long long t0 = clock64();
#pragma unroll 1
    for (int it = 0; it < iters; ++it) {
#pragma unroll
        for (int i = 0; i < UNROLL; i++) x[i] = x[i] * b + a;
    }
    long long t1 = clock64();
    T s = 0;
#pragma unroll
    for (int i = 0; i < UNROLL; i++) s += x[i];
    if (s == (T)-98765) out[0] = s;
    if (threadIdx.x == 0 && blockIdx.x == 0) *clk = t1 - t0;
}

template <int UNROLL>
__global__ __launch_bounds__(128) void k_imad(int *out, int a, int b, int iters, long long *clk) {
    int x[UNROLL];
#pragma unroll
    for (int i = 0; i < UNROLL; i++) x[i] = a + i;
    long long t0 = clock64();
#pragma unroll 1
    for (int it = 0; it < iters; ++it) {
#pragma unroll
        for (int i = 0; i < UNROLL; i++) x[i] = x[i] * b + a;
    }
    long long t1 = clock64();
    int s = 0;
#pragma unroll
    for (int i = 0; i < UNROLL; i++) s += x[i];
    if (s == -98765) out[0] = s;
    if (threadIdx.x == 0 && blockIdx.x == 0) *clk = t1 - t0;
}

template <int UNROLL>
__global__ __launch_bounds__(128) void k_hfma2(__half2 *out, __half2 a, __half2 b, int iters,
                                               long long *clk) {
    __half2 x[UNROLL];
#pragma unroll
    for (int i = 0; i < UNROLL; i++) x[i] = a;
    long long t0 = clock64();
#pragma unroll 1
    for (int it = 0; it < iters; ++it) {
#pragma unroll
        for (int i = 0; i < UNROLL; i++) x[i] = __hfma2(x[i], b, a);
    }
    long long t1 = clock64();
    __half2 s = x[0];
#pragma unroll
    for (int i = 1; i < UNROLL; i++) s = __hadd2(s, x[i]);
    if (__low2float(s) == -98765.0f) out[0] = s;
    if (threadIdx.x == 0 && blockIdx.x == 0) *clk = t1 - t0;
}

using namespace nvcuda;
template <int NACC>
__global__ __launch_bounds__(128) void k_wmma(float *out, const __half *A, const __half *B,
                                              int iters, long long *clk) {
    wmma::fragment<wmma::matrix_a, 16, 16, 16, __half, wmma::row_major> fa;
    wmma::fragment<wmma::matrix_b, 16, 16, 16, __half, wmma::col_major> fb;
    wmma::fragment<wmma::accumulator, 16, 16, 16, float> acc[NACC];
    wmma::load_matrix_sync(fa, A, 16);
    wmma::load_matrix_sync(fb, B, 16);
#pragma unroll
    for (int i = 0; i < NACC; i++) wmma::fill_fragment(acc[i], 0.0f);
    long long t0 = clock64();
#pragma unroll 1
    for (int it = 0; it < iters; ++it) {
#pragma unroll
        for (int i = 0; i < NACC; i++) wmma::mma_sync(acc[i], fa, fb, acc[i]);
    }
    long long t1 = clock64();
    float s = 0;
#pragma unroll
    for (int i = 0; i < NACC; i++) s += acc[i].x[0];
    if (s == -98765.0f) out[0] = s;
    if (threadIdx.x == 0 && blockIdx.x == 0) *clk = t1 - t0;
}

// ---------------------------------------------------------------- memory

__global__ void k_read(const float4 *__restrict__ in, float4 *out, size_t n4) {
    size_t i = blockIdx.x * (size_t)blockDim.x + threadIdx.x;
    size_t stride = gridDim.x * (size_t)blockDim.x;
    float4 acc = make_float4(0, 0, 0, 0);
    for (; i < n4; i += stride) {
        float4 v = in[i];
        acc.x += v.x; acc.y += v.y; acc.z += v.z; acc.w += v.w;
    }
    if (acc.x == 1e30f) out[0] = acc;
}

__global__ void k_copy(const float4 *__restrict__ in, float4 *__restrict__ o, size_t n4) {
    size_t i = blockIdx.x * (size_t)blockDim.x + threadIdx.x;
    size_t stride = gridDim.x * (size_t)blockDim.x;
    for (; i < n4; i += stride) o[i] = in[i];
}

// ---------------------------------------------------------------- harness

static double g_locked_ghz = 1.380;

struct Res { double secs; double meas_ghz; };

template <class F>
static Res timeit(F launch, long long *d_clk) {
    launch();
    CHK(cudaDeviceSynchronize());
    cudaEvent_t a, b; CHK(cudaEventCreate(&a)); CHK(cudaEventCreate(&b));
    CHK(cudaEventRecord(a));
    launch();
    CHK(cudaEventRecord(b));
    CHK(cudaEventSynchronize(b));
    CHK(cudaGetLastError());
    float ms = 0; CHK(cudaEventElapsedTime(&ms, a, b));
    CHK(cudaEventDestroy(a)); CHK(cudaEventDestroy(b));
    long long cyc = 0;
    if (d_clk) CHK(cudaMemcpy(&cyc, d_clk, sizeof(cyc), cudaMemcpyDeviceToHost));
    Res r; r.secs = ms / 1e3;
    r.meas_ghz = d_clk ? (double)cyc / (r.secs * 1e9) : 0.0;
    return r;
}

// fma_ops = number of FMA (or IMAD, or HMMA-FMA) operations actually issued.
// peak_fma_sm_clk = architectural FMA/SM/clock for this pipe on CC 7.0.
static void report(const char *name, double fma_ops, double secs, double meas_ghz,
                   int sms, double peak_fma_sm_clk, double flops_per_fma, const char *unit) {
    double rate_fma = fma_ops / secs;
    double peak_fma = peak_fma_sm_clk * sms * g_locked_ghz * 1e9;
    printf("  %-18s %8.3f T%s/s  |  peak %7.3f T%s/s @%.0fMHz  |  %6.1f%% of peak  |  "
           "%5.1f FMA/SM/clk (arch %.0f)  |  meas clk %6.1f MHz\n",
           name, rate_fma * flops_per_fma / 1e12, unit,
           peak_fma * flops_per_fma / 1e12, unit, g_locked_ghz * 1000.0,
           100.0 * rate_fma / peak_fma,
           rate_fma / (sms * g_locked_ghz * 1e9), peak_fma_sm_clk,
           meas_ghz * 1000.0);
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
    int dev = 0;
    if (argc > 1) dev = atoi(argv[1]);
    if (argc > 2) g_locked_ghz = atof(argv[2]) / 1000.0;
    // GV100_BDF selects by PCI address; the bus id is printed either way so a wrong-device
    // run is self-evident in the log rather than a plausible-looking number.
    cudaDeviceProp p = pick_device(dev);

    const int sms = p.multiProcessorCount;
    const double theo_bw = 2.0 * p.memoryClockRate * 1e3 * (p.memoryBusWidth / 8);

    printf("========================================================================\n");
    printf("%s   CC %d.%d   %d SM   RM SMclk %.0f MHz   MEMclk %.0f MHz   bus %d bit\n",
           p.name, p.major, p.minor, sms, p.clockRate / 1000.0,
           p.memoryClockRate / 1000.0, p.memoryBusWidth);
    printf("peaks computed at locked clock %.0f MHz | theoretical mem BW %.1f GB/s | L2 %d KB\n",
           g_locked_ghz * 1000.0, theo_bw / 1e9, p.l2CacheSize / 1024);
    printf("========================================================================\n");

    void *d_out; CHK(cudaMalloc(&d_out, 1024));
    long long *d_clk; CHK(cudaMalloc(&d_clk, sizeof(long long)));

    // 128 threads/block, 8 blocks/SM = 1024 threads/SM = 32 warps -- half the 2048 max, so a
    // 32-register-per-thread kernel uses half the register file and cannot spill.
    const int TH = 128, BPSM = 8;
    const int blocks = sms * BPSM;
    const double threads = (double)blocks * TH;
    const double warps = threads / 32.0;

    printf("\n-- arithmetic pipes (%d blocks x %d thr = %.0f thr/SM) -------------------\n",
           blocks, TH, threads / sms);

    { const int U = 8, it = 8192;
      Res r = timeit([&]{ k_fma<float, U><<<blocks, TH>>>((float*)d_out, 1.0f, 1.000001f, it, d_clk); }, d_clk);
      report("FP32 FMA", (double)U * it * threads, r.secs, r.meas_ghz, sms, 64, 2.0, "FLOP"); }

    { const int U = 8, it = 8192;
      Res r = timeit([&]{ k_fma<double, U><<<blocks, TH>>>((double*)d_out, 1.0, 1.000001, it, d_clk); }, d_clk);
      report("FP64 FMA", (double)U * it * threads, r.secs, r.meas_ghz, sms, 32, 2.0, "FLOP"); }

    { const int U = 8, it = 8192;
      Res r = timeit([&]{ k_imad<U><<<blocks, TH>>>((int*)d_out, 1, 3, it, d_clk); }, d_clk);
      report("INT32 IMAD", (double)U * it * threads, r.secs, r.meas_ghz, sms, 64, 1.0, "IMAD"); }

    { const int U = 8, it = 8192;
      __half2 ha = __floats2half2_rn(1.0f, 1.0f), hb = __floats2half2_rn(1.0001f, 1.0001f);
      Res r = timeit([&]{ k_hfma2<U><<<blocks, TH>>>((__half2*)d_out, ha, hb, it, d_clk); }, d_clk);
      // one HFMA2 = 2 lanes x 1 FMA = 2 FMA
      report("FP16x2 FMA", 2.0 * U * it * threads, r.secs, r.meas_ghz, sms, 128, 2.0, "FLOP"); }

    { const int NACC = 2, it = 8192;
      __half *dA, *dB;
      CHK(cudaMalloc(&dA, 512)); CHK(cudaMalloc(&dB, 512));
      CHK(cudaMemset(dA, 0, 512)); CHK(cudaMemset(dB, 0, 512));
      Res r = timeit([&]{ k_wmma<NACC><<<blocks, TH>>>((float*)d_out, dA, dB, it, d_clk); }, d_clk);
      // one 16x16x16 mma_sync per warp = 4096 FMA
      report("TensorCore HMMA", 4096.0 * NACC * it * warps, r.secs, r.meas_ghz, sms, 512, 2.0, "FLOP");
      CHK(cudaFree(dA)); CHK(cudaFree(dB)); }

    printf("\n-- memory ---------------------------------------------------------------\n");
    {
        size_t bytes = 2ull << 30;
        size_t n4 = bytes / sizeof(float4);
        float4 *a, *b;
        CHK(cudaMalloc(&a, bytes)); CHK(cudaMalloc(&b, bytes));
        CHK(cudaMemset(a, 1, bytes));
        int gb = sms * 32;
        Res r1 = timeit([&]{ k_read<<<gb, TH>>>(a, b, n4); }, nullptr);
        printf("  %-18s %8.1f GB/s  |  %.1f%% of theoretical %.1f GB/s\n", "device read",
               bytes / r1.secs / 1e9, 100.0 * (bytes / r1.secs) / theo_bw, theo_bw / 1e9);
        Res r2 = timeit([&]{ k_copy<<<gb, TH>>>(a, b, n4); }, nullptr);
        printf("  %-18s %8.1f GB/s  |  %.1f%% of theoretical\n", "device copy (r+w)",
               2.0 * bytes / r2.secs / 1e9, 100.0 * (2.0 * bytes / r2.secs) / theo_bw);
        CHK(cudaFree(a)); CHK(cudaFree(b));
    }
    {
        size_t bytes = 256ull << 20;
        void *h, *d;
        CHK(cudaMallocHost(&h, bytes)); CHK(cudaMalloc(&d, bytes));
        Res r1 = timeit([&]{ cudaMemcpy(d, h, bytes, cudaMemcpyHostToDevice); }, nullptr);
        Res r2 = timeit([&]{ cudaMemcpy(h, d, bytes, cudaMemcpyDeviceToHost); }, nullptr);
        printf("  %-18s %8.2f GB/s\n", "H2D pinned", bytes / r1.secs / 1e9);
        printf("  %-18s %8.2f GB/s\n", "D2H pinned", bytes / r2.secs / 1e9);
        CHK(cudaFreeHost(h)); CHK(cudaFree(d));
    }

    CHK(cudaFree(d_out)); CHK(cudaFree(d_clk));
    printf("\n");
    return 0;
}
