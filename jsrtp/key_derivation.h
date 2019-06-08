#ifndef __KEY_DERIVATION_H__
#define __KEY_DERIVATION_H__
#include "counter_mode.h"
#include "aes.h"
#include "utils.h"
#include <map>

class KeyDerivation
{
public:
	enum class Label : uint8_t
	{
		srtp_encryption_key,
		srtp_authentication_key,
		srtp_salting_key,
		srtcp_encryption_key,
		srtcp_authentication_key,
		srtcp_salting_key
	};

	static constexpr int MASTER_KEY_LEN = 16;
	static constexpr int MASTER_SALT_LEN = 14;
	static constexpr int INDEX_LEN = 6;
	static constexpr int PRF_M = 16;

	ByteVector derive_key(uint64_t index, Label label, uint64_t n);

	void set_master_key(ByteVector master_key);
	void set_master_salt(ByteVector master_salt);

	bool must_derive_key(uint64_t index, Label label);
	void set_kdr(int power);

private:
	uint64_t get_r(uint64_t index) const;
	CTR<AES> prf;
	ByteVector master_salt;
	int kdr = 0;
	struct DerivedKey
	{
		uint64_t r = 0;
		bool initial_derived = false;
	};
	std::map<Label, DerivedKey> derived_keys;
};

#endif