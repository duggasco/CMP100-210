// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright 2026 duggasco
// gv100_validate.cu -- numerical validation of the lifted fp64 / tensor-core throttle.
//
// A speed number is worthless if the arithmetic is wrong.  Lifting the SM speed-select throttle
// changes the issue rate of the fp64 and tensor pipes; this runs real GEMMs on them and checks
// every output element against a CPU reference, so "16x faster" is backed by "and still correct".
//
//   DGEMM   N x N fp64, checked against a full double-precision CPU reference (exact same
//           accumulation order is not required -- the tolerance is set from the condition of the
//           sum, not from a bitwise expectation).
//   HGEMM   N x N via wmma 16x16x16, fp16 in / fp32 accumulate, checked against a CPU reference
//           computed in double and rounded, with a tolerance that reflects fp16 input rounding.
//
// build: nvcc -O3 -arch=sm_70 -Xcompiler -fopenmp -o gv100_validate gv100_validate.cu

#include <cstdio>
#include <cstring>
#include <cctype>
#include <cstdlib>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <cuda_runtime.h>
#include <mma.h>
#define CHK(x) do { cudaError_t e_=(x); if(e_){printf("CUDA err line %d: %s\n",__LINE__,cudaGetErrorString(e_));exit(1);} } while(0)

static const int TS = 16;

__global__ void dgemm(const double *A, const double *B, double *C, int N) {
    __shared__ double As[TS][TS], Bs[TS][TS];
    int row = blockIdx.y * TS + threadIdx.y, col = blockIdx.x * TS + threadIdx.x;
    double acc = 0.0;
    for (int t = 0; t < N / TS; ++t) {
        As[threadIdx.y][threadIdx.x] = A[row * N + t * TS + threadIdx.x];
        Bs[threadIdx.y][threadIdx.x] = B[(t * TS + threadIdx.y) * N + col];
        __syncthreads();
#pragma unroll
        for (int k = 0; k < TS; ++k) acc += As[threadIdx.y][k] * Bs[k][threadIdx.x];
        __syncthreads();
    }
    C[row * N + col] = acc;
}

using namespace nvcuda;
// one warp per 16x16 output tile
__global__ void hgemm(const __half *A, const __half *B, float *C, int N) {
    int warp = (blockIdx.x * blockDim.x + threadIdx.x) / 32;
    int tiles = N / 16;
    int tr = warp / tiles, tc = warp % tiles;
    if (tr >= tiles) return;
    wmma::fragment<wmma::accumulator, 16, 16, 16, float> acc;
    wmma::fill_fragment(acc, 0.0f);
    for (int k = 0; k < tiles; ++k) {
        wmma::fragment<wmma::matrix_a, 16, 16, 16, __half, wmma::row_major> fa;
        wmma::fragment<wmma::matrix_b, 16, 16, 16, __half, wmma::row_major> fb;
        wmma::load_matrix_sync(fa, A + tr * 16 * N + k * 16, N);
        wmma::load_matrix_sync(fb, B + k * 16 * N + tc * 16, N);
        wmma::mma_sync(acc, fa, fb, acc);
    }
    wmma::store_matrix_sync(C + tr * 16 * N + tc * 16, acc, N, wmma::mem_row_major);
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
    int N = (argc > 1) ? atoi(argv[1]) : 1024;
    int dev = (argc > 2) ? atoi(argv[2]) : 0;
    pick_device(dev);
    printf("validating %dx%d GEMMs\n", N, N);
    size_t n2 = (size_t)N * N;

    std::vector<double> hA(n2), hB(n2), hC(n2), ref(n2);
    srand(12345);
    for (size_t i = 0; i < n2; i++) {
        hA[i] = (double)rand() / RAND_MAX - 0.5;
        hB[i] = (double)rand() / RAND_MAX - 0.5;
    }

    // ---------------- CPU reference (double) ----------------
    printf("  cpu reference ... "); fflush(stdout);
#pragma omp parallel for
    for (int i = 0; i < N; i++)
        for (int k = 0; k < N; k++) {
            double a = hA[(size_t)i * N + k];
            for (int j = 0; j < N; j++) ref[(size_t)i * N + j] += a * hB[(size_t)k * N + j];
        }
    printf("done\n");

    // ---------------- DGEMM on the fp64 pipe ----------------
    {
        double *dA, *dB, *dC;
        CHK(cudaMalloc(&dA, n2 * 8)); CHK(cudaMalloc(&dB, n2 * 8)); CHK(cudaMalloc(&dC, n2 * 8));
        CHK(cudaMemcpy(dA, hA.data(), n2 * 8, cudaMemcpyHostToDevice));
        CHK(cudaMemcpy(dB, hB.data(), n2 * 8, cudaMemcpyHostToDevice));
        dim3 blk(TS, TS), grd(N / TS, N / TS);
        dgemm<<<grd, blk>>>(dA, dB, dC, N);
        CHK(cudaDeviceSynchronize());
        cudaEvent_t a, b; CHK(cudaEventCreate(&a)); CHK(cudaEventCreate(&b));
        const int REP = 20;
        CHK(cudaEventRecord(a));
        for (int r = 0; r < REP; r++) dgemm<<<grd, blk>>>(dA, dB, dC, N);
        CHK(cudaEventRecord(b)); CHK(cudaEventSynchronize(b));
        float ms = 0; CHK(cudaEventElapsedTime(&ms, a, b));
        CHK(cudaMemcpy(hC.data(), dC, n2 * 8, cudaMemcpyDeviceToHost));
        // Normwise criterion, not elementwise-relative.  The GPU sums in 16-element tiles and the
        // CPU sums linearly, so for random +/-0.5 inputs the true dot products sit near zero and
        // individual elements are arbitrarily ill-conditioned -- an elementwise relative test
        // measures the conditioning of the data, not the correctness of the pipe.  The standard
        // bound for a length-N dot product is  |err| <= N * eps * max|A| * max|B| , and 16x that
        // is generous for any summation order.
        double maxA = 0, maxB = 0;
        for (size_t i = 0; i < n2; i++) { maxA = fmax(maxA, fabs(hA[i])); maxB = fmax(maxB, fabs(hB[i])); }
        const double eps = 2.220446049250313e-16;
        double bound = 16.0 * N * eps * maxA * maxB;
        double maxabs = 0, maxrel = 0; size_t bad = 0;
        for (size_t i = 0; i < n2; i++) {
            double d = fabs(hC[i] - ref[i]);
            if (d > maxabs) maxabs = d;
            double s = fabs(ref[i]);
            if (s > 1e-6) maxrel = fmax(maxrel, d / s);
            if (d > bound) bad++;
        }
        double gf = 2.0 * N * N * (double)N * REP / (ms / 1e3) / 1e12;
        printf("  DGEMM  fp64   %8.3f TFLOP/s   max abs err %.3e (bound %.3e)   over bound: %zu   %s\n",
               gf, maxabs, bound, bad, bad == 0 ? "CORRECT" : "MISMATCH");
        printf("                (worst elementwise rel err %.3e -- data conditioning, not pipe error)\n",
               maxrel);
        CHK(cudaFree(dA)); CHK(cudaFree(dB)); CHK(cudaFree(dC));
    }

    // ---------------- HGEMM on the tensor cores ----------------
    {
        std::vector<__half> hAh(n2), hBh(n2);
        std::vector<float> hCf(n2);
        for (size_t i = 0; i < n2; i++) { hAh[i] = __float2half((float)hA[i]); hBh[i] = __float2half((float)hB[i]); }
        // reference from the ROUNDED inputs, so the comparison isolates the pipe, not fp16 input error
        std::vector<double> href(n2, 0.0);
#pragma omp parallel for
        for (int i = 0; i < N; i++)
            for (int k = 0; k < N; k++) {
                double a = (double)__half2float(hAh[(size_t)i * N + k]);
                for (int j = 0; j < N; j++) href[(size_t)i * N + j] += a * (double)__half2float(hBh[(size_t)k * N + j]);
            }
        __half *dA, *dB; float *dC;
        CHK(cudaMalloc(&dA, n2 * 2)); CHK(cudaMalloc(&dB, n2 * 2)); CHK(cudaMalloc(&dC, n2 * 4));
        CHK(cudaMemcpy(dA, hAh.data(), n2 * 2, cudaMemcpyHostToDevice));
        CHK(cudaMemcpy(dB, hBh.data(), n2 * 2, cudaMemcpyHostToDevice));
        int warps = (N / 16) * (N / 16), threads = 128;
        int blocks = (warps * 32 + threads - 1) / threads;
        hgemm<<<blocks, threads>>>(dA, dB, dC, N);
        CHK(cudaDeviceSynchronize());
        cudaEvent_t a, b; CHK(cudaEventCreate(&a)); CHK(cudaEventCreate(&b));
        const int REP = 50;
        CHK(cudaEventRecord(a));
        for (int r = 0; r < REP; r++) hgemm<<<blocks, threads>>>(dA, dB, dC, N);
        CHK(cudaEventRecord(b)); CHK(cudaEventSynchronize(b));
        float ms = 0; CHK(cudaEventElapsedTime(&ms, a, b));
        CHK(cudaMemcpy(hCf.data(), dC, n2 * 4, cudaMemcpyDeviceToHost));
        double maxabs = 0; size_t bad = 0;
        // fp32 accumulation of N fp16 products: a few ulp of fp32 times sqrt(N) is generous
        double tol = 1e-3 * sqrt((double)N);
        for (size_t i = 0; i < n2; i++) {
            double d = fabs((double)hCf[i] - href[i]);
            if (d > maxabs) maxabs = d;
            if (d > tol) bad++;
        }
        double tf = 2.0 * N * N * (double)N * REP / (ms / 1e3) / 1e12;
        printf("  HGEMM  tensor %8.3f TFLOP/s   max abs err %.3e (tol %.1e)   over tol: %zu   %s\n",
               tf, maxabs, tol, bad, bad == 0 ? "CORRECT" : "MISMATCH");
        CHK(cudaFree(dA)); CHK(cudaFree(dB)); CHK(cudaFree(dC));
    }
    return 0;
}
