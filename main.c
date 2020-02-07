#include <stdint.h>
#include <stdio.h>
#include "boring.h"

void println_hex(uint8_t* data, int size) {
  while (size > 0) {
    printf("%02x", *data);
    data++;
    size--;
  }
  printf("\n");
}

int main(int argc, uint8_t *argv[]) {
  extern void vector_chacha20(uint8_t *out, const uint8_t *in,
			      size_t in_len, const uint8_t key[32],
			      const uint8_t nonce[12], uint32_t counter);
  const int len = 64 * 2000;
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
  boring_chacha20(golden, (const uint8_t*)(data), len, key, nonce, counter);
  printf("golden: ");
  println_hex(golden, 32);

  uint8_t vector[len];
  vector_chacha20(vector, (const uint8_t*)(data), len, key, nonce, counter);
  printf("vector: ");
  println_hex(vector, 32);

  if (memcmp(golden, vector, len)) {
    printf("vector output doesn't match boring golden output\n");
  } else {
    printf("PASS\n");
  }
}
