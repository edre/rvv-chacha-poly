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
  printf("instruction count: %d\n", end-start);

  uint8_t vector[len];
  start = instruction_counter();
  vector_chacha20(vector, (const uint8_t*)(data), len, key, nonce, counter);
  end = instruction_counter();
  printf("vector: ");
  println_hex(vector, 32);
  printf("instruction count: %d\n", end-start);

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
  boring_poly1305_init(&state, key);
  boring_poly1305_update(&state, data, 16);
  uint8_t *sig = malloc(16); // gets corrupted if I define it on the stack?
  boring_poly1305_finish(&state, sig);
  uint8_t *sig2 = malloc(16);
  vector_poly1305(data, 16, key, sig2);

  bool pass = memcmp(sig, sig2, 16) == 0;

  if (verbose || !pass) {
    printf("boring mac: ");
    println_hex(sig, 16);
    printf("vector mac: ");
    println_hex(sig2, 16);
  }

  free(sig);
  free(sig2);
  return pass;
}

void test_polys() {
  const uint8_t zero[32] ={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  const uint8_t one[32] = {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  const uint8_t key[32] = {1, 4, 9, 16, 25, 36, 49, 64, 81, 100, 121, 144, 169, 196, 225, 255,
  			   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  const uint8_t data[32] = "Setec astronomy;too many secrets";
  bool pass = test_poly(data, 16, key, true);

  // random test
  FILE* f = fopen("/dev/urandom", "r");
  for (int i = 0; i < 100; i++) {
    const int len = 16;
    fread((uint8_t*)key, 32, 1, f);
    fread((uint8_t*)data, len, 1, f);
    pass = pass && test_poly(data, len, key, false);
  }
  fclose(f);

  if (pass) {
    printf("poly PASS\n");
  } else {
    printf("poly FAIL\n");
  }

}

int main(int argc, uint8_t *argv[]) {
  extern uint32_t vlmax_u32();
  //printf("VLMAX in blocks: %d\n", vlmax_u32());
  //test_chacha();
  //printf("\n");
  test_polys();
}
