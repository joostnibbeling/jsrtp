#ifndef __KEY_DERIVATION_H_
#define __KEY_DERIVATION_H_
#include "block_mode.h"
#include "block_cipher.h"
#include "utils.h"

class KeyDerivation
{
public:
	static constexpr int MASTER_KEY_LEN = 16;
	static constexpr int MASTER_SALT_LEN = 14;
	static constexpr int INDEX_LEN = 6;
	static constexpr int PRF_M = 16;

	ByteVector derive_key(uint64_t index, uint8_t label, uint64_t n);
	void set_master_key(ByteVector master_key);
	void set_master_salt(ByteVector master_salt);
private:
	uint64_t get_r(uint64_t index);

	bool initial_derived = false;
	bool must_derive_key(uint64_t index, uint64_t r);
	CTR<AES> prf;
	uint64_t kdr = 0;

	ByteVector master_salt;
};

#endif