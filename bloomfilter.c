/*
 * bloomfilter.c
 *
 *  Created on: Apr 23, 2017
 *      Author: falak
 */

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define FNV_PRIME_32 16777619
#define FNV_OFFSET_32 2166136261U

typedef struct bf_t {
	int *bloom[8];
} bf_t;

bf_t *create_bf() {

	bf_t *bf = (bf_t *) malloc(sizeof(bf_t));

	bf->bloom[0] = (int *) calloc(62500, sizeof(int));
	bf->bloom[1] = (int *) calloc(62500, sizeof(int));
	bf->bloom[2] = (int *) calloc(62500, sizeof(int));
	bf->bloom[3] = (int *) calloc(62500, sizeof(int));
	bf->bloom[4] = (int *) calloc(62500, sizeof(int));
	bf->bloom[5] = (int *) calloc(62500, sizeof(int));
	bf->bloom[6] = (int *) calloc(62500, sizeof(int));
	bf->bloom[7] = (int *) calloc(62500, sizeof(int));

	return bf;
}

//djb2 hash function
uint32_t h0(char *str) {
	uint32_t hash = 5381;
	int c;
	while (c = *str++) {
		hash = ((hash << 5) + hash) + c;
	}
	hash = (hash % 2000000);
	return hash;
}

//djb2a has function
uint32_t h1(char *str) {
	uint32_t hash = 5381;
	int c;
	while (c = *str++) {
		hash = ((hash << 5) + hash) ^ c;
	}
	hash = (hash % 2000000);
	return hash;
}

//sdbm hash function
uint32_t h2(char *str) {
	uint32_t hash = 0;
	int c;

	while (c = *str++) {
		hash = c + (hash << 6) + (hash << 16) - hash;
	}

	hash = (hash % 2000000);
	return hash;
}

//jenkins_one_at_a_time hash fnction
uint32_t h3(char *key) {
	size_t len = strlen(key);
	uint32_t hash, i;
	for (hash = i = 0; i < len; ++i) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	hash = (hash % 2000000);
	return hash;
}

//FNV1a
uint32_t h4(const char *s) {
	uint32_t hash = FNV_OFFSET_32, i;
	for (i = 0; i < strlen(s); i++) {
		hash = hash ^ (s[i]); // xor next byte into the bottom of the hash
		hash = hash * FNV_PRIME_32; // Multiply by prime number found to work well
	}
	hash = (hash % 2000000);
	return hash;
}

//FNV1
uint32_t h5(const char *s) {
	uint32_t hash = FNV_OFFSET_32, i;
	for (i = 0; i < strlen(s); i++) {
		hash = hash * FNV_PRIME_32; // Multiply by prime number found to work well
		hash = hash ^ (s[i]); // xor next byte into the bottom of the hash
	}
	hash = (hash % 2000000);
	return hash;
}

//murmur3_32a
uint32_t h6(const char* key) {
	size_t len = strlen(key);
	uint32_t h = 0xbc9f1d34;

	if (len > 3) {
		const uint32_t* key_x4 = (const uint32_t*) key;
		size_t i = len >> 2;
		do {
			uint32_t k = *key_x4++;
			k *= 0xcc9e2d51;
			k = (k << 15) | (k >> 17);
			k *= 0x1b873593;
			h ^= k;
			h = (h << 13) | (h >> 19);
			h += (h << 2) + 0xe6546b64;
		} while (--i);
		key = (const uint8_t*) key_x4;
	}
	if (len & 3) {
		size_t i = len & 3;
		uint32_t k = 0;
		key = &key[i - 1];
		do {
			k <<= 8;
			k |= *key--;
		} while (--i);
		k *= 0xcc9e2d51;
		k = (k << 15) | (k >> 17);
		k *= 0x1b873593;
		h ^= k;
	}
	h ^= len;
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;

	h = (h % 2000000);
	return h;
}

//murmur3_32b
uint32_t h7(const char* key) {
	size_t len = strlen(key);
	uint32_t h = 701;
	if (len > 3) {
		const uint32_t* key_x4 = (const uint32_t*) key;
		size_t i = len >> 2;
		do {
			uint32_t k = *key_x4++;
			k *= 0xcc9e2d51;
			k = (k << 15) | (k >> 17);
			k *= 0x1b873593;
			h ^= k;
			h = (h << 13) | (h >> 19);
			h += (h << 2) + 0xe6546b64;
		} while (--i);
		key = (const uint8_t*) key_x4;
	}
	if (len & 3) {
		size_t i = len & 3;
		uint32_t k = 0;
		key = &key[i - 1];
		do {
			k <<= 8;
			k |= *key--;
		} while (--i);
		k *= 0xcc9e2d51;
		k = (k << 15) | (k >> 17);
		k *= 0x1b873593;
		h ^= k;
	}
	h ^= len;
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;

	h = (h % 2000000);
	return h;
}

//Sets the kth bit in the array A

void setbit(int A[], uint32_t k) {

	int i = k / 32;
	int pos = k % 32;
	unsigned int flag = 1;
	flag = flag << pos;
	A[i] = A[i] | flag;

}

int checkbit(int A[], uint32_t k) {
	int check = 0;
	int i = k / 32;
	int pos = k % 32;

	unsigned int flag = 1;  // flag = 0000.....00001

	flag = flag << pos;     // flag = 0000...010...000   (shifted k positions)

	// Check the bit at the k-th position in A[i]
	if (A[i] & flag) {
		// k-th bit is 1
		check = 1;
	} else {
		// k-th bit is 0
		check = 0;
	}

	return check;

}
void insert_bf(bf_t *b, char *s) {
	uint32_t *hash = (uint32_t *) calloc(8, sizeof(uint32_t));

	hash[0] = h0(s);
	hash[1] = h1(s);
	hash[2] = h2(s);
	hash[3] = h3(s);
	hash[4] = h4(s);
	hash[5] = h5(s);
	hash[6] = h6(s);
	hash[7] = h7(s);

	int i = 0;

	for (i = 0; i < 8; i++) {
		setbit(b->bloom[i], hash[i]);
	}

}

int is_element(bf_t *b, char *s) {
	uint32_t *hash = (uint32_t *) calloc(8, sizeof(uint32_t));
	int *check = (int *) calloc(8, sizeof(int));
	int ret=1;

	hash[0] = h0(s);
	hash[1] = h1(s);
	hash[2] = h2(s);
	hash[3] = h3(s);
	hash[4] = h4(s);
	hash[5] = h5(s);
	hash[6] = h6(s);
	hash[7] = h7(s);

	int i = 0;
	for (i = 0; i < 8; i++) {
		check[i] = checkbit(b->bloom[i], hash[i]);
		ret = ret & check[i];
	}
	return ret;
}




