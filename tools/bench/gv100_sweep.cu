// gv100_sweep.cu -- sensitivity check for gv100_pipes.cu.
//
// A pipe measured at 1/16 of architectural rate is only evidence of a throttle if the kernel
// was not simply latency-bound.  This sweeps the number of independent dependency chains and
// the occupancy for each pipe: a pipe-limited result is FLAT across the sweep, a latency-bound
// one climbs with more chains.  Prints FMA/SM/clk, the unit in which a hardware rate divider
// shows up as a round number.
//
// build: nvcc -O3 -arch=sm_70 --extended-lambda -o gv100_sweep gv100_sweep.cu

#include <cstdio>
#include <cstring>
#include <cctype>
#include <cstdlib>
#include <cstdlib>
#include <cuda_runtime.h>
#include <mma.h>
#define CHK(x) do { cudaError_t e_=(x); if(e_){printf("CUDA err %d: %s\n",__LINE__,cudaGetErrorString(e_));exit(1);} } while(0)

template <typename T, int U>
__global__ void k_fma(T *out, T a, T b, int iters) {
    T x[U];
#pragma unroll
    for (int i=0;i<U;i++) x[i]=a+(T)i;
#pragma unroll 1
    for (int it=0; it<iters; ++it) {
#pragma unroll
        for (int i=0;i<U;i++) x[i]=x[i]*b+a;
    }
    T s=0;
#pragma unroll
    for (int i=0;i<U;i++) s+=x[i];
    if (s==(T)-98765) out[0]=s;
}

using namespace nvcuda;
template <int NACC>
__global__ void k_wmma(float *out, const __half *A, const __half *B, int iters) {
    wmma::fragment<wmma::matrix_a,16,16,16,__half,wmma::row_major> fa;
    wmma::fragment<wmma::matrix_b,16,16,16,__half,wmma::col_major> fb;
    wmma::fragment<wmma::accumulator,16,16,16,float> acc[NACC];
    wmma::load_matrix_sync(fa,A,16); wmma::load_matrix_sync(fb,B,16);
#pragma unroll
    for (int i=0;i<NACC;i++) wmma::fill_fragment(acc[i],0.0f);
#pragma unroll 1
    for (int it=0; it<iters; ++it) {
#pragma unroll
        for (int i=0;i<NACC;i++) wmma::mma_sync(acc[i],fa,fb,acc[i]);
    }
    float s=0;
#pragma unroll
    for (int i=0;i<NACC;i++) s+=acc[i].x[0];
    if (s==-98765.0f) out[0]=s;
}

static double GHZ=1.380; static int SMS=80;
template <class F> static double secs_of(F f){
    f(); CHK(cudaDeviceSynchronize());
    cudaEvent_t a,b; CHK(cudaEventCreate(&a)); CHK(cudaEventCreate(&b));
    CHK(cudaEventRecord(a)); f(); CHK(cudaEventRecord(b)); CHK(cudaEventSynchronize(b));
    float ms=0; CHK(cudaEventElapsedTime(&ms,a,b)); CHK(cudaGetLastError());
    CHK(cudaEventDestroy(a)); CHK(cudaEventDestroy(b)); return ms/1e3;
}
static void line(const char*tag,int U,int th,int bpsm,double fma,double s,double arch){
    double per = fma/s/(SMS*GHZ*1e9);
    printf("   %-12s chains=%-3d %4d thr x %d blk/SM (%4d thr/SM)  %7.2f FMA/SM/clk  = 1/%-5.2f of arch %.0f\n",
           tag,U,th,bpsm,th*bpsm,per,arch/per,arch);
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

int main(int argc,char**argv){
    if(argc>1) GHZ=atof(argv[1])/1000.0;
    int dev = (argc>2) ? atoi(argv[2]) : 0;
    cudaDeviceProp p = pick_device(dev); SMS=p.multiProcessorCount;
    printf("sweep on %s, %d SM, peaks at %.0f MHz\n", p.name, SMS, GHZ*1000);
    void*o; CHK(cudaMalloc(&o,1024));
    __half *dA,*dB; CHK(cudaMalloc(&dA,512)); CHK(cudaMalloc(&dB,512));
    CHK(cudaMemset(dA,0,512)); CHK(cudaMemset(dB,0,512));
    const int it=16384;

    printf("\n FP32 (arch 64 FMA/SM/clk)\n");
    { int th=128,b=SMS*8; double n=(double)th*b;
      line("fp32",4,th,8, 4.0*it*n, secs_of([&]{k_fma<float,4><<<b,th>>>((float*)o,1.f,1.000001f,it);}),64); }
    { int th=128,b=SMS*8; double n=(double)th*b;
      line("fp32",16,th,8,16.0*it*n, secs_of([&]{k_fma<float,16><<<b,th>>>((float*)o,1.f,1.000001f,it);}),64); }
    { int th=256,b=SMS*4; double n=(double)th*b;
      line("fp32",16,th,4,16.0*it*n, secs_of([&]{k_fma<float,16><<<b,th>>>((float*)o,1.f,1.000001f,it);}),64); }

    printf("\n FP64 (arch 32 FMA/SM/clk)\n");
    { int th=128,b=SMS*8; double n=(double)th*b;
      line("fp64",4,th,8, 4.0*it*n, secs_of([&]{k_fma<double,4><<<b,th>>>((double*)o,1.0,1.000001,it);}),32); }
    { int th=128,b=SMS*8; double n=(double)th*b;
      line("fp64",8,th,8, 8.0*it*n, secs_of([&]{k_fma<double,8><<<b,th>>>((double*)o,1.0,1.000001,it);}),32); }
    { int th=128,b=SMS*8; double n=(double)th*b;
      line("fp64",16,th,8,16.0*it*n, secs_of([&]{k_fma<double,16><<<b,th>>>((double*)o,1.0,1.000001,it);}),32); }
    { int th=256,b=SMS*4; double n=(double)th*b;
      line("fp64",8,th,4, 8.0*it*n, secs_of([&]{k_fma<double,8><<<b,th>>>((double*)o,1.0,1.000001,it);}),32); }
    { int th=64,b=SMS*16; double n=(double)th*b;
      line("fp64",8,th,16,8.0*it*n, secs_of([&]{k_fma<double,8><<<b,th>>>((double*)o,1.0,1.000001,it);}),32); }

    printf("\n TensorCore HMMA 16x16x16 (arch 512 FMA/SM/clk)\n");
    { int th=128,b=SMS*8; double w=(double)th*b/32.0;
      line("hmma",1,th,8, 4096.0*1*it*w, secs_of([&]{k_wmma<1><<<b,th>>>((float*)o,dA,dB,it);}),512); }
    { int th=128,b=SMS*8; double w=(double)th*b/32.0;
      line("hmma",2,th,8, 4096.0*2*it*w, secs_of([&]{k_wmma<2><<<b,th>>>((float*)o,dA,dB,it);}),512); }
    { int th=128,b=SMS*8; double w=(double)th*b/32.0;
      line("hmma",4,th,8, 4096.0*4*it*w, secs_of([&]{k_wmma<4><<<b,th>>>((float*)o,dA,dB,it);}),512); }
    { int th=256,b=SMS*4; double w=(double)th*b/32.0;
      line("hmma",4,th,4, 4096.0*4*it*w, secs_of([&]{k_wmma<4><<<b,th>>>((float*)o,dA,dB,it);}),512); }
    printf("\n");
    return 0;
}
