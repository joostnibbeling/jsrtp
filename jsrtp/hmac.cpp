#include "HMAC.h"

HMAC::HMAC() : hash(std::make_unique<SHA1>()) {}

HMAC::HMAC(std::unique_ptr<HashFunction> in_hash) : hash(std::move(in_hash)) {}

void HMAC::set_key(std::vector<uint8_t> in_key)
{
	key = std::move(in_key);
}

void HMAC::append(const uint8_t* in, uint64_t len)
{
	std::copy(in, in + len, std::back_inserter(message));
}

void HMAC::append(const std::vector<uint8_t>& in)
{
	std::copy(in.begin(), in.end(), std::back_inserter(message));
}

std::vector<uint8_t> HMAC::get_digest()
{
	unsigned int block_size = hash->get_block_size();
	
	if (key.size() > block_size)
	{
		hash->append(key);
		key = hash->get_digest();
	}
	
	if (key.size() < block_size)
	{
		int to_pad = block_size - key.size();
		std::fill_n(std::back_inserter(key), to_pad, 0);
	}

	std::vector<uint8_t> o_key_pad (block_size);
	std::transform(key.begin(), key.end(), o_key_pad.begin(), [](uint8_t in) { return in ^ 0x5c; });

	std::vector<uint8_t> i_key_pad (block_size);
	std::transform(key.begin(), key.end(), i_key_pad.begin(), [](uint8_t in) {return in ^ 0x36; });

	hash->append(i_key_pad);
	hash->append(message);

	message.clear();

	auto inner_digest = hash->get_digest();
	hash->append(o_key_pad);
	hash->append(inner_digest);

	return  hash->get_digest();
}