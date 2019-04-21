#include "block_mode.h"

CTR::CTR() : cipher(std::make_unique<AES>()), ctr{} {}


CTR::CTR(std::unique_ptr<Cipher> in_cipher) : cipher(std::move(in_cipher)), ctr{} {}

void CTR::set_key(ByteVector in_key)
{
	cipher->set_key(std::move(in_key));
}

void CTR::set_iv(ByteVector in_iv)
{
	ctr = std::move(in_iv);
}

ByteVector CTR::encrypt(const ByteVector& plain_text)
{
	int block_size = cipher->get_block_size();
	int blocks = plain_text.size() / block_size;
	ByteVector cipher_text;
	cipher_text.reserve(plain_text.size());

	for (int i = 0; i < blocks; ++i)
	{
		auto plain_begin = plain_text.begin() + block_size * i;
		auto encrypted_ctr = cipher->encrypt(ctr);

		std::transform(encrypted_ctr.begin(), encrypted_ctr.end(),
			plain_begin,
			std::back_inserter(cipher_text),
			[](uint8_t in1, uint8_t in2) {return in1 ^ in2; });

		increment_ctr();
	}

	return cipher_text;

}

ByteVector CTR::decrypt(const ByteVector& cipher_text)
{
	return encrypt(cipher_text);
}

void CTR::reset_ctr()
{
	std::fill(ctr.begin(), ctr.end(), 0);
}

void CTR::increment_ctr()
{
	for (auto it = ctr.rbegin(); it != ctr.rend(); ++it)
	{
		++(*it);
		if (*it != 0) break;
	}
}