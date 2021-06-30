/* Copyright 2021 0x7ff
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "libdimentio.h"

#define IO_OBJECT_NULL ((io_object_t)0)
#define kIODeviceTreePlane "IODeviceTree"

#ifndef MIN
#	define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

typedef char io_string_t[512];
typedef uint32_t IOOptionBits;
typedef mach_port_t io_object_t;
typedef io_object_t io_registry_entry_t;

CFStringRef crypto_hash_method;
unsigned t1sz_boot;

kern_return_t
IOObjectRelease(io_object_t);

io_registry_entry_t
IORegistryEntryFromPath(mach_port_t, const io_string_t);

CFTypeRef
IORegistryEntryCreateCFProperty(io_registry_entry_t, CFStringRef, CFAllocatorRef, IOOptionBits);

extern const mach_port_t kIOMasterPortDefault;

int
main2(int argc, char **argv) {
	uint8_t *entangled_nonce = NULL;
	io_registry_entry_t chosen;
	int ret = EXIT_FAILURE;
	uint64_t nonce;
	bool entangled;
	CFDataRef hash;
	size_t i;

	if(argc != 1 && argc != 2) {
		printf("Usage: %s [nonce]\n", argv[0]);
	} else if((argc == 1 || sscanf(argv[1], "0x%016" PRIx64, &nonce) == 1) && dimentio_init(0, NULL, NULL) == KERN_SUCCESS) {
		if (t1sz_boot != 0) {
			entangled_nonce = (uint8_t*)malloc(CC_SHA384_DIGEST_LENGTH * sizeof(uint8_t));
		} else if ((chosen = IORegistryEntryFromPath(kIOMasterPortDefault, kIODeviceTreePlane ":/chosen")) != IO_OBJECT_NULL) {
			if ((hash = IORegistryEntryCreateCFProperty(chosen, CFSTR("crypto-hash-method"), kCFAllocatorDefault, kNilOptions)) != NULL) {
				if (CFGetTypeID(hash) == CFDataGetTypeID()) {
					if ((crypto_hash_method = CFStringCreateFromExternalRepresentation(NULL, hash, kCFStringEncodingUTF8)) != NULL) {
						if (CFStringCompare(crypto_hash_method, CFSTR("sha1\0"), 0) == kCFCompareEqualTo) {
							entangled_nonce = (uint8_t*)malloc(CC_SHA1_DIGEST_LENGTH * sizeof(uint8_t));
						} else if (CFStringCompare(crypto_hash_method, CFSTR("sha2-384\0"), 0) == kCFCompareEqualTo) {
							entangled_nonce = (uint8_t*)malloc(CC_SHA384_DIGEST_LENGTH * sizeof(uint8_t));
						}
					}
				}
				CFRelease(hash);
			}
			IOObjectRelease(chosen);
		}
		if(entangled_nonce != NULL && dimentio(&nonce, argc == 2, entangled_nonce, &entangled) == KERN_SUCCESS) {
			if(argc == 1) {
				printf("Current nonce is 0x%016" PRIX64 "\n", nonce);
			} else {
				printf("Set nonce to 0x%016" PRIX64 "\n", nonce);
			}
			if(entangled) {
				printf("entangled_apnonce: ");
				for (i = 0; i < MIN(CC_SHA384_DIGEST_LENGTH, 32); ++i) {
					printf("%02" PRIX8, entangled_nonce[i]);
				}
			} else {
				printf("apnonce: ");
				if (CFStringCompare(crypto_hash_method, CFSTR("sha1\0"), 0) == kCFCompareEqualTo) {
					for (i = 0; i < CC_SHA1_DIGEST_LENGTH; ++i) {
						printf("%02" PRIX8, entangled_nonce[i]);
					}
				} else for (i = 0; i < MIN(CC_SHA384_DIGEST_LENGTH, 32); ++i) {
					printf("%02" PRIX8, entangled_nonce[i]);
				}
			}
			putchar('\n');
			CFRelease(crypto_hash_method);
			free(entangled_nonce);
			ret = 0;
		}
		dimentio_term();
	}
	return ret;
}
