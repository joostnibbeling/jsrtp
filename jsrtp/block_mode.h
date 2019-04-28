#ifndef __BLOCK_MODE_H
#define __BLOCK_MODE_H
#include "utils.h"
#include "block_cipher.h"

template <typename Cipher>
class BlockMode
{
public:
	virtual void set_key(ByteVector) = 0;
	virtual void set_iv(ByteVector) = 0;
	virtual ByteVector encrypt(const ByteVector& plain_text) = 0;
	virtual ByteVector decrypt(const ByteVector& cipher_text) = 0;
	virtual ~BlockMode() {}
	Cipher cipher;
};

template<typename Cipher>
class EBC : BlockMode<Cipher>
{
public:
	virtual void set_key(ByteVector in_key);
	virtual void set_iv(ByteVector in_iv) {};
	virtual ByteVector encrypt(const ByteVector& plain_text);
	virtual ByteVector decrypt(const ByteVector& cipher_text);
};

template<typename Cipher>
void EBC<Cipher>::set_key(ByteVector in_key)
{
	this->cipher.set_key(std::move(in_key));
}

template<typename Cipher>
ByteVector EBC<Cipher>::encrypt(const ByteVector& plain_text)
{
	return this->cipher.encrypt(plain_text);
}

template<typename Cipher>
ByteVector EBC<Cipher>::decrypt(const ByteVector& cipher_text)
{
	return this->cipher.decrypt(cipher_text);
}

template<typename Cipher>
class CTR : BlockMode<Cipher>
{
public:
	virtual void set_key(ByteVector in_key);
	virtual void set_iv(ByteVector in_iv);
	virtual ByteVector encrypt(const ByteVector& plain_text);
	virtual ByteVector decrypt(const ByteVector& cipher_text);
private:
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
	encrypt_ctr();
}

template<typename Cipher>
ByteVector CTR<Cipher>::encrypt(const ByteVector& plain_text)
{
	if (ctr.size() == 0)
	{
		throw std::exception("CTR mode IV not set");
	}
	
	int to_encrypt = plain_text.size();
	ByteVector cipher_text;
	cipher_text.reserve(plain_text.size());

	while (to_encrypt > 0)
	{
		int encrypted_ctr_left = Cipher::BLOCK_SIZE - ctr_offset;
		int encrypting = std::min(encrypted_ctr_left, to_encrypt);

		std::transform(encrypted_ctr.begin() + ctr_offset, encrypted_ctr.begin() + ctr_offset + encrypting,
			plain_text.end() - to_encrypt,
			std::back_inserter(cipher_text),
			[](uint8_t in1, uint8_t in2) { return in1 ^ in2; } );

		to_encrypt -= encrypting;
		ctr_offset += encrypting;
		if (ctr_offset >= Cipher::BLOCK_SIZE)
		{
			increment_ctr();
			encrypt_ctr();
		}
	}

	return cipher_text;

}

template<typename Cipher>
ByteVector CTR<Cipher>::decrypt(const ByteVector& cipher_text)
{
	return encrypt(cipher_text);
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
	encrypted_ctr = this->cipher.encrypt(ctr);
	ctr_offset = 0;
}

#endif