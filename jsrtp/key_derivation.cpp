#include "key_derivation.h"

void KeyDerivation::set_master_key(ByteVector master_key)
{
	prf.set_key(std::move(master_key));
	initial_derived = false;
}

void KeyDerivation::set_master_salt(ByteVector in_master_salt)
{
	master_salt = std::move(in_master_salt);
	initial_derived = false;
}

uint64_t KeyDerivation::get_r(uint64_t index)
{
	if (kdr == 0) return 0;
	else return index / kdr;
}

ByteVector KeyDerivation::derive_key(uint64_t index, uint8_t label, uint64_t n)
{
	auto r = get_r(index);
	if (must_derive_key(index, r))
	{
		ByteVector x;
		x.reserve(PRF_M);

		if (master_salt.size() > 0)
		{
			std::fill_n(std::back_inserter(x), MASTER_SALT_LEN - INDEX_LEN - 1, 0);
			x.push_back(label);
			std::generate_n(std::back_inserter(x), INDEX_LEN, LittleEndianToBytes<uint64_t, 48>(r));

			std::transform(master_salt.begin(),
				master_salt.end(),
				x.begin(),
				x.begin(),
				[](uint8_t in1, uint8_t in2) { return in1 ^ in2; });

			std::fill_n(std::back_inserter(x), PRF_M - MASTER_SALT_LEN, 0);
		}
		else
		{
			std::generate_n(std::back_inserter(x), INDEX_LEN, LittleEndianToBytes<uint64_t, 48>(r));
			std::fill_n(std::back_inserter(x), PRF_M - INDEX_LEN, 0);
		}

		prf.set_iv(std::move(x));

		ByteVector empty(static_cast<unsigned int>(n));
		std::fill_n(empty.begin(), n, 0);
		auto key = prf.encrypt(empty);
		return key;
	}

	return {};
}

bool KeyDerivation::must_derive_key(uint64_t index, uint64_t r)
{
	return true;

	if (!initial_derived)
	{
		initial_derived = true;
		return true;
	}
	else if (r == 0)
	{
		return false;
	}
	
	return index % r == 0;
}