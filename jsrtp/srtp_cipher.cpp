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

void SrtpAESCM::encrypt(SrtpPacket& packet)
{
	// IV = (salt * 2^16) XOR (ssrc * 2^64) XOR (srtp_index * 2^16)
	// Everything right padded with 0 to 16 bytes.

	// Allowed salt length is 14
	// salt * 2 ^ 16 is 16 bytes
	// requires no padding.
	ByteVector IV(16);
	std::transform(salt.begin(), salt.end(), IV.begin(), IV.begin(), [](uint8_t x, uint8_t y) {return x ^ y; });

	// SSRC is 4 bytes.
	// SSRC * 2^64 is 12 bytes
	// 4 bytes of right padding
	auto ssrc_bytes_gen = LittleEndianToBytes(packet.get_ssrc());
	std::transform(IV.begin() + 4, IV.begin() + 8, IV.begin()+4, [&ssrc_bytes_gen](uint8_t x) {return x ^ ssrc_bytes_gen(); });

	// srtp_index is 6 bytes
	// srtp_index * 2 ^ 16 is 8 bytes
	// 8 bytes or right padding
	auto srtp_index_bytes_gen = LittleEndianToBytes<6>(packet.get_srtp_index());
	std::transform(IV.begin() + 8, IV.begin() + 14, IV.begin() + 8, [&srtp_index_bytes_gen](uint8_t x) { return srtp_index_bytes_gen() ^ x; });

	aes.set_iv(std::move(IV));
	aes.encrypt(packet.get_payload_start(), packet.get_payload_length());
}

void SrtpAESCM::decrypt(SrtpPacket& packet)
{
	// IV = (salt * 2^16) XOR (ssrc * 2^64) XOR (srtp_index * 2^16)
	// Everything right padded with 0 to 16 bytes.

	// Allowed salt length is 14
	// salt * 2 ^ 16 is 16 bytes
	// requires no padding.
	ByteVector IV(16);
	std::transform(salt.begin(), salt.end(), IV.begin(), IV.begin(), [](uint8_t x, uint8_t y) {return x ^ y; });

	// SSRC is 4 bytes.
	// SSRC * 2^64 is 12 bytes
	// 4 bytes of right padding
	auto ssrc_bytes_gen = LittleEndianToBytes(packet.get_ssrc());
	std::transform(IV.begin() + 4, IV.begin() + 8, IV.begin()+4, [&ssrc_bytes_gen](uint8_t x) {return x ^ ssrc_bytes_gen(); });

	// srtp_index is 6 bytes
	// srtp_index * 2 ^ 16 is 8 bytes
	// 8 bytes or right padding
	auto srtp_index_bytes_gen = LittleEndianToBytes<6>(packet.get_srtp_index());
	std::transform(IV.begin() + 8, IV.begin() + 14, IV.begin() + 8, [&srtp_index_bytes_gen](uint8_t x) { return srtp_index_bytes_gen() ^ x; });

	aes.set_iv(std::move(IV));
	aes.decrypt(packet.get_payload_start(), packet.get_payload_length());
}

