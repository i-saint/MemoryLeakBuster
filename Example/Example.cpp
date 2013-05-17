// created by i-saint
// distributed under Creative Commons Attribution (CC BY) license.
// https://github.com/i-saint/MemoryLeakBuster

#include <cstdlib>

int main(int argc, char* argv[])
{
    static void *I_am_leaking = malloc(1024);

    for(int i=0; i<16; ++i) {
        void *mem1 = malloc(512);
        free(mem1);
        for(int j=0; j<16; ++j) {
            void *mem2 = malloc(256);
            free(mem2);
            for(int k=0; k<16; ++k) {
                void *mem3 = malloc(128);
                free(mem3);
            }
        }
    }
}
