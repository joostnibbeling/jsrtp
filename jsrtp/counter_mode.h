#ifndef __BLOCK_MODE_H
#define __BLOCK_MODE_H
#include "utils.h"
#include "aes.h"

template<typename Cipher>
class CTR
{
public:
	void set_key(ByteVector in_key);
	void set_iv(ByteVector in_iv);

	template<typename Container>
	void encrypt(Container& plain_text);

	template<typename Iter>
	void encrypt(Iter plain_text, int size);

	template<typename Container>
	void decrypt(Container& cipher_text);

	template<typename Iter>
	void decrypt(Iter plain_text, int size);
private:
	Cipher cipher;
	void reset_ctr();
	void increment_ctr();
	void encrypt_ctr();

	ByteVector ctr;
	ByteVector encrypted_ctr;
	int ctr_offset = 0;
};

template<typename Cipher>
void CTR<Cipher>::set_key(ByteVector in_key)
{
	this->cipher.set_key(std::move(in_key));
}

template<typename Cipher>
void CTR<Cipher>::set_iv(ByteVector in_iv)
{
	ctr = std::move(in_iv);
	encrypted_ctr.resize(ctr.size());
	encrypt_ctr();
}

template<typename Cipher>
template<typename Container>
void CTR<Cipher>::encrypt(Container& plain_text)
{
	encrypt(plain_text.begin(), plain_text.size());
}

template<typename Cipher>
template<typename Container>
void CTR<Cipher>::decrypt(Container& cipher_text)
{
	return encrypt(cipher_text);
}

template<typename Cipher>
template<typename Iter>
void CTR<Cipher>::encrypt(Iter plain_text, int size)
{
	if (ctr.size() == 0)
	{
		throw std::exception("CTR mode IV not set");
	}

	int to_encrypt = size;
	Iter end = plain_text + size;

	while (to_encrypt > 0)
	{
		int encrypted_ctr_left = Cipher::BLOCK_SIZE - ctr_offset;
		int encrypting = std::min(encrypted_ctr_left, to_encrypt);

		std::transform(
			encrypted_ctr.begin() + ctr_offset, encrypted_ctr.begin() + ctr_offset + encrypting,
			end - to_encrypt,
			end - to_encrypt,
			[](uint8_t in1, uint8_t in2) { return in1 ^ in2; });

		to_encrypt -= encrypting;
		ctr_offset += encrypting;
		if (ctr_offset >= Cipher::BLOCK_SIZE)
		{
			increment_ctr();
			encrypt_ctr();
		}
	}
}

template<typename Cipher>
template<typename Iter>
void CTR<Cipher>::decrypt(Iter plain_text, int size)
{
	return encrypt(plain_text, size);
}

template<typename Cipher>
void CTR<Cipher>::reset_ctr()
{
	std::fill(ctr.begin(), ctr.end(), 0);
}

template<typename Cipher>
void CTR<Cipher>::increment_ctr()
{
	for (auto it = ctr.rbegin(); it != ctr.rend(); ++it)
	{
		++(*it);
		if (*it != 0) break;
	}
}

template<typename Cipher>
void CTR<Cipher>::encrypt_ctr()
{
	std::copy(ctr.begin(), ctr.end(), encrypted_ctr.begin());
	this->cipher.encrypt(encrypted_ctr);
	ctr_offset = 0;
}

#endif