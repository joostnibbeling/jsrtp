#include "key_derivation.h"
#include <cmath>

void KeyDerivation::set_master_key(ByteVector master_key)
{
	prf.set_key(std::move(master_key));
}

void KeyDerivation::set_master_salt(ByteVector in_master_salt)
{
	master_salt = std::move(in_master_salt);
}

uint64_t KeyDerivation::get_r(uint64_t index)
{
	if (kdr == 0) return 0;
	else return index / kdr;
}

void KeyDerivation::set_kdr(int power)
{
	if (power < 0 || power > 24)
	{
		throw std::exception("Invalid key deviration rate");
	}

	kdr = static_cast<int>(pow(2, power));
}

ByteVector KeyDerivation::derive_key(uint64_t index, Label label, uint64_t n)
{
	auto r = get_r(index);
	
	ByteVector x;
	x.reserve(PRF_M);

	if (master_salt.size() > 0)
	{
		// Before XORing x with master salt, x should be of equal length to MASTER_SALT_LEN
		// Appended to x is 1 byte label, followed by INDEX_LEN byte packet index,
		// So prepend first MASTER_SALT_LEN - INDEX_LEN - 1 leading 0s

		std::fill_n(std::back_inserter(x), MASTER_SALT_LEN - INDEX_LEN - 1, 0);
		x.push_back(static_cast<uint8_t>(label));
		std::generate_n(std::back_inserter(x), INDEX_LEN, LittleEndianToBytes<uint64_t, 48>(r));

		std::transform(master_salt.begin(),
			master_salt.end(),
			x.begin(),
			x.begin(),
			[](uint8_t in1, uint8_t in2) { return in1 ^ in2; });

		// Pad with zeros at end until proper input m for PRF is reached
		std::fill_n(std::back_inserter(x), PRF_M - MASTER_SALT_LEN, 0);
	}
	else
	{
		// No master salt here.
		// Simply append label with index and pad until proper input length m for PRF is reached.
		x.push_back(static_cast<uint8_t>(label));
		std::generate_n(std::back_inserter(x), INDEX_LEN, LittleEndianToBytes<uint64_t, 48>(r));
		std::fill_n(std::back_inserter(x), PRF_M - INDEX_LEN, 0);
	}

	prf.set_iv(std::move(x));

	ByteVector empty(static_cast<unsigned int>(n));
	std::fill_n(empty.begin(), n, 0);
	auto key = prf.encrypt(empty);

	derived_keys[label].initial_derived = true;
	derived_keys[label].r = r;

	return key;
}

bool KeyDerivation::must_derive_key(uint64_t index, Label label)
{
	auto r = get_r(index);

	if (!derived_keys[label].initial_derived)
	{
		return true;
	}
	else if(derived_keys[label].r != r)
	{
		return true;
	}

	return false;
}