/* standalone_main.c — single-file run-once driver for the wolfTPM libFuzzer
 * harnesses (no libFuzzer runtime). Reads ONE input file and feeds its bytes to
 * LLVMFuzzerTestOneInput, so the same harness object doubles as a crash reproducer.
 *
 * If the harness defines LLVMFuzzerInitialize (fwtpm_fuzz does), call it once
 * first, mirroring libFuzzer's contract. The symbol is declared weak so harnesses
 * without it (fuzz_asn_cert) link cleanly.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);
__attribute__((weak)) int LLVMFuzzerInitialize(int* argc, char*** argv);

int main(int argc, char** argv) {
    FILE* f;
    long size;
    uint8_t* data;
    size_t r;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
        return 1;
    }
    if (LLVMFuzzerInitialize) {
        LLVMFuzzerInitialize(&argc, &argv);
    }
    f = fopen(argv[1], "rb");
    if (f == NULL) {
        fprintf(stderr, "failed to open %s\n", argv[1]);
        return 2;
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size < 0) { fclose(f); return 2; }
    data = (uint8_t*)malloc((size_t)size ? (size_t)size : 1);
    if (data == NULL) { fclose(f); return 3; }
    r = fread(data, 1, (size_t)size, f);
    fclose(f);
    (void)r;
    LLVMFuzzerTestOneInput(data, (size_t)size);
    free(data);
    return 0;
}
