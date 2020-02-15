#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "boring.h"

void println_hex(uint8_t* data, int size) {
  while (size > 0) {
    printf("%02x", *data);
    data++;
    size--;
  }
  printf("\n");
}

// TODO: test the vector doesn't write past the end
// test function with multiple length inputs (optional printing)
// test non-block sized lengths

extern uint64_t instruction_counter();

void test_chacha() {
  extern void vector_chacha20(uint8_t *out, const uint8_t *in,
			      size_t in_len, const uint8_t key[32],
			      const uint8_t nonce[12], uint32_t counter);

  const int len = 64 * 101;
  uint8_t data[len];
  uint32_t rand = 1;
  for (int i = 0; i < len; i++) {
    rand *= 101;
    rand %= 16777213; // random prime
    data[i] = (uint8_t)(rand);
  }
  const uint8_t key[32] = "Setec astronomy;too many secrets";
  const uint8_t nonce[12] = "BurnAfterUse";
  int counter = 0;

  uint8_t golden[len];
  uint64_t start = instruction_counter();
  boring_chacha20(golden, (const uint8_t*)(data), len, key, nonce, counter);
  uint64_t end = instruction_counter();
  printf("golden: ");
  println_hex(golden, 32);
  printf("inst_count=%d, inst/byte=%.02f\n", end - start, (float)(end - start)/len);

  uint8_t vector[len];
  start = instruction_counter();
  vector_chacha20(vector, (const uint8_t*)(data), len, key, nonce, counter);
  end = instruction_counter();
  printf("vector: ");
  println_hex(vector, 32);
  printf("inst_count=%d, inst/byte=%.02f\n", end - start, (float)(end - start)/len);

  if (memcmp(golden, vector, len)) {
    printf("chacha FAIL\n");
  } else {
    printf("chacha PASS\n");
  }
}

bool test_poly(const uint8_t* data, size_t len, const uint8_t key[32], bool verbose) {
  extern uint64_t vector_poly1305(const uint8_t* in, size_t len,
				  const uint8_t key[32], uint8_t sig[16]);

  poly1305_state state;
  uint8_t *sig = malloc(16); // gets corrupted if I define it on the stack?
  uint64_t start = instruction_counter();
  boring_poly1305_init(&state, key);
  boring_poly1305_update(&state, data, len);
  boring_poly1305_finish(&state, sig);
  uint64_t end = instruction_counter();
  uint64_t boring_count = end - start;

  uint8_t *sig2 = malloc(16);
  start = instruction_counter();
  uint64_t mid = vector_poly1305(data, len, key, sig2);
  end = instruction_counter();

  bool pass = memcmp(sig, sig2, 16) == 0;

  if (verbose || !pass) {
    printf("boring mac: ");
    println_hex(sig, 16);
    printf("inst_count=%d, inst/byte=%.02f\n", boring_count, (float)(boring_count)/len);
    printf("vector mac: ");
    println_hex(sig2, 16);
    printf("precomputation=%d, processing=%d, inst/byte=%.02f\n",
	   mid - start, end - mid, (float)(end - mid)/len);
  }

  free(sig);
  free(sig2);
  return pass;
}

void test_polys() {
  const int big_len = 1024;
  uint8_t *zero = malloc(2000);
  uint8_t *max_bits = malloc(big_len);
  memset(max_bits, 0xff, big_len);
  const uint8_t one[32] = {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  const uint8_t key[32] = {1, 4, 9, 16, 25, 36, 49, 64, 81, 100, 121, 144, 169, 196, 225, 255,
  			   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  const uint8_t data[272] = "Setec astronomy;too many secrets";
  bool pass = test_poly(max_bits, big_len, max_bits, true);

  if (!pass)
    goto end;

  // random test
  FILE* f = fopen("/dev/urandom", "r");
  const int max_len = 1000;
  uint8_t *rand = malloc(max_len);
  for (int len = 16; len <= max_len; len += 16) {
    fread((uint8_t*)key, 32, 1, f);
    fread((uint8_t*)rand, len, 1, f);
    if (!test_poly(data, len, key, false)) {
      printf("failed random input len=%d\n", len);
      pass = false;
      break;
    }
  }
  free(rand);
  fclose(f);

 end:
  if (pass) {
    printf("poly PASS\n");
  } else {
    printf("poly FAIL\n");
  }

  free(zero);
  free(max_bits);
}

int main(int argc, uint8_t *argv[]) {
  extern uint32_t vlmax_u32();
  printf("VLMAX in blocks: %d\n", vlmax_u32());
  test_chacha();
  printf("\n");
  test_polys();
}
