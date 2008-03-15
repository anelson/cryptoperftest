// crypto_perf_test.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <crtdbg.h>
#include <exception>
#include <cmath>

#include <tomcrypt.h>

static void init();
static double getAesDecryptionsPerSecond();
static double getpbkdfAesDecryptionsPerSecond();
static void doAesDecrypt(unsigned char* ciphertext, unsigned char* raw_aes_key, unsigned char* plaintext);
static void doPbkdfAesDecrypt(unsigned char* ciphertext, unsigned char* password, unsigned char* plaintext);
static double computeOpsPerSecond(LARGE_INTEGER& start, LARGE_INTEGER& end, unsigned int numOps);

#define AES_KEY_SIZE_BYTES			16
#define AES_BLOCK_SIZE_BYTES		16
#define	PBKDF_SALT_SIZE_BYTES		16
#define PBKDF_ITERATION_COUNT		2000
#define	INPUT_PASSWORD_SIZE_BYTES	8

#define AES_DECRYPTS				100000000
#define PBKDF_AES_DECRYPTS			1000

#define HMAC_HASH_FUNCTION			"sha256"
#define PRNG						"fortuna"

#define TRY_LTC(x) \
	{ \
		int ret = (x); \
		static const char* func = #x; \
		if (ret != CRYPT_OK) { \
			::sprintf_s(crypto_error_message_buffer,  \
				"Error invoking \n\n\t%s\n\nError: %s\n",  \
				func, \
				::error_to_string(ret)); \
			throw std::exception(crypto_error_message_buffer); \
		} \
	} \


static prng_state prng;
static unsigned char salt[PBKDF_SALT_SIZE_BYTES];
static unsigned char raw_aes_key[AES_KEY_SIZE_BYTES];
static unsigned char password[INPUT_PASSWORD_SIZE_BYTES];
static unsigned char ciphertext[AES_BLOCK_SIZE_BYTES];
static int hmac_hash_index;
static int prng_index;
static struct _prng_descriptor* prng_desc;

static char crypto_error_message_buffer[1024];


int _tmain(int argc, _TCHAR* argv[])
{
	//Test how much computational overhead PKCS 5.2 password key derivation adds to AES encryption
	//The objective is to determine how many bits of strength the PBKDF2 adds to a given input passphrase
	double aesDecryptsPerSecond;
	double pbkdfAesDecryptsPerSecond;
	try {
		init();

		aesDecryptsPerSecond = getAesDecryptionsPerSecond();
		pbkdfAesDecryptsPerSecond = getpbkdfAesDecryptionsPerSecond();
	} catch (std::exception& e) {
		::printf("Error: %s", e.what());
		return -1;
	}

	double pbkdfTimeMultiplier = aesDecryptsPerSecond / pbkdfAesDecryptsPerSecond;

	//Each additional bit in an AES key increases the brute force effort by roughly a factor of two
	//We assume the additional time added by PBKDF corresponds to roughtly the same additional computational complexity
	//
	//Thus, if we compute log2(pbkdfTimeMultipler), that gives us n such that 2^n = pbkdfTimeMultiplier.  n is then
	//the additional "bits" of strength added to the input key, if we x take bits to be a measure of the time required to brute-force
	// 2^x possible AES keys

	//A property of logarithms is that the base b log of x == ln(x) / ln(b)
	double ln2 = std::log(static_cast<double>(2));
	double lnTimeMultipler = std::log(pbkdfTimeMultiplier);
	double log2TimeMultipler = lnTimeMultipler / ln2;

	::_tprintf(_T("%0.2f AES decrypts/second\n"), aesDecryptsPerSecond);
	::wprintf(L"%0.2f PBKDF(%S, %d iterations)/AES decrypts/second\n", pbkdfAesDecryptsPerSecond, HMAC_HASH_FUNCTION, PBKDF_ITERATION_COUNT);
	::_tprintf(_T("PBKDF complexity multiplier: %0.2f\n"), pbkdfTimeMultiplier);
	::_tprintf(_T("log2(multiplier): %0.2f\n"), log2TimeMultipler);
}

static void init() {
	::register_prng(&::fortuna_desc);
	::register_cipher(&::aes_desc);
	::register_hash(&::sha1_desc);
	
	prng_index = ::find_prng(PRNG);
	if (prng_index == -1) {
		throw std::exception("failed to find PRNG");
	}

	TRY_LTC(::prng_descriptor[prng_index].start(&prng));
	int entropyBitsNeeded = (PBKDF_SALT_SIZE_BYTES + AES_KEY_SIZE_BYTES + INPUT_PASSWORD_SIZE_BYTES + AES_BLOCK_SIZE_BYTES) * 8;
	while (entropyBitsNeeded > 0) {
		unsigned char entropy[8];
		unsigned long bytes = ::rng_get_bytes(entropy, sizeof(entropy), NULL);
		TRY_LTC(::prng_descriptor[prng_index].add_entropy(entropy, bytes, &prng));
		entropyBitsNeeded -= bytes*8;
	}

	TRY_LTC(prng_descriptor[prng_index].ready(&prng));

	prng_descriptor[prng_index].read(raw_aes_key, sizeof(raw_aes_key), &prng);
	prng_descriptor[prng_index].read(salt, sizeof(salt), &prng);
	prng_descriptor[prng_index].read(password, sizeof(password), &prng);
	prng_descriptor[prng_index].read(ciphertext, sizeof(ciphertext), &prng);
	
	
}

static double getAesDecryptionsPerSecond() {
	::_tprintf(_T("Doing %d AES decryptions..."), AES_DECRYPTS);

	LARGE_INTEGER start;
	::QueryPerformanceCounter(&start);

	unsigned char plaintext[AES_BLOCK_SIZE_BYTES];

	for (unsigned int i = 0; i < AES_DECRYPTS; i++) {
		doAesDecrypt(ciphertext, raw_aes_key, plaintext);
	}

	LARGE_INTEGER end;
	::QueryPerformanceCounter(&end);

	::_tprintf(_T("done\n"));

	return computeOpsPerSecond(start, end, AES_DECRYPTS);
}

static double getpbkdfAesDecryptionsPerSecond() {
	::_tprintf(_T("Doing %d PBKDF2/AES decryptions..."), PBKDF_AES_DECRYPTS);

	LARGE_INTEGER start;
	::QueryPerformanceCounter(&start);

	unsigned char plaintext[AES_BLOCK_SIZE_BYTES];

	for (unsigned int i = 0; i < PBKDF_AES_DECRYPTS; i++) {
		doPbkdfAesDecrypt(ciphertext, password, plaintext);
	}

	LARGE_INTEGER end;
	::QueryPerformanceCounter(&end);

	::_tprintf(_T("done\n"));

	return computeOpsPerSecond(start, end, PBKDF_AES_DECRYPTS);
}

static void doAesDecrypt(unsigned char* ciphertext, unsigned char* raw_aes_key, unsigned char* plaintext) {
	symmetric_key aes_key;
	TRY_LTC(::aes_setup(raw_aes_key, 
		AES_KEY_SIZE_BYTES,
		0,
		&aes_key));
	TRY_LTC(::aes_ecb_decrypt(ciphertext, plaintext, &aes_key));
}

static void doPbkdfAesDecrypt(unsigned char* ciphertext, unsigned char* password, unsigned char* plaintext) {
	unsigned char derived_aes_key[AES_KEY_SIZE_BYTES];
	unsigned long outlen = sizeof(derived_aes_key);

	TRY_LTC(::pkcs_5_alg2(password,
		INPUT_PASSWORD_SIZE_BYTES,
		salt,
		PBKDF_SALT_SIZE_BYTES,
		PBKDF_ITERATION_COUNT,
		hmac_hash_index,
		derived_aes_key,
		&outlen));

	_ASSERT(outlen == sizeof(derived_aes_key));

	doAesDecrypt(ciphertext, derived_aes_key, plaintext);
}

static double computeOpsPerSecond(LARGE_INTEGER& start, LARGE_INTEGER& end, unsigned int numOps) {
	LARGE_INTEGER freq;
	::QueryPerformanceFrequency(&freq);

	double counterPulsesPerSecond = static_cast<double>(freq.QuadPart);
	double pulses = static_cast<double>(end.QuadPart - start.QuadPart);
	double seconds = pulses / counterPulsesPerSecond;
	double totalOps = numOps;
	double opsPerSecond = totalOps / seconds;

	return opsPerSecond;
}
