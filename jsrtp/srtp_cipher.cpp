#include "srtp_cipher.h"

SrtpAESCM::SrtpAESCM(int key_len, int salt_len) : n_e(key_len), n_s(salt_len)
{
	if (key_len != 16 &&
		key_len != 24 &&
		key_len != 32)
	{
		throw std::invalid_argument("Invalid session key length for SRTP AES CM");
	}

	if (salt_len != 14)
	{
		throw std::invalid_argument("Invalid session salt length for SRTP AES CM");
	}
}

int SrtpAESCM::get_key_length()
{
	return n_e;
}

int SrtpAESCM::get_salt_length()
{
	return n_s;
}

void SrtpAESCM::set_key(ByteVector key)
{
	aes.set_key(std::move(key));
}

void SrtpAESCM::set_salt(ByteVector salt)
{
	this->salt = std::move(salt);
}

void SrtpAESCM::encrypt(const rtp_header& hdr, unsigned char* payload, int payload_len, uint64_t index)
{
	ByteVector IV(16);
	std::transform(salt.begin(), salt.end(), IV.begin(), IV.begin(), [](uint8_t x, uint8_t y) {return x ^ y; });
	const uint8_t* ssrc = reinterpret_cast<const uint8_t*>(&hdr.ssrc);
	std::transform(ssrc, ssrc+4, IV.begin() + 4, IV.begin() + 4, [](uint8_t x, uint8_t y) {return x ^ y; });
	LittleEndianToBytesGen<uint64_t, 6> gen(index);
	std::transform(IV.begin() + 8, IV.begin() + 14, IV.begin() + 8, [&gen](uint8_t x) { return gen() ^ x; });

	aes.set_iv(std::move(IV));

	ByteVector pl(payload_len);
	std::copy(payload, payload + payload_len, pl.begin());
	aes.encrypt(pl);
	std::copy(pl.begin(), pl.end(), payload);
}

