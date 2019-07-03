#include "srtp_auth.h"

SrtpHmacSha1::SrtpHmacSha1(int key_length, int tag_length) : n_a(key_length), tag_len(tag_length)
{
	if (n_a != 20)
	{
		throw std::invalid_argument("Invalid authentication session key length");
	}

	if (tag_len != 4 && tag_len != 10)
	{
		throw std::invalid_argument("Invalid authentication tag length for HMAC-SHA1");
	}
}

int SrtpHmacSha1::get_key_length()
{
	return n_a;
}

int SrtpHmacSha1::get_auth_length()
{
	return tag_len;
}

void SrtpHmacSha1::set_key(ByteVector key)
{
	auth.set_key(std::move(key));
}

void SrtpHmacSha1::authenticate(SrtpPacket& packet)
{
	// Authenticated portion:
	// Header || Encrypted Payload || ROC
	auth.append(packet.get_header_start(), packet.get_packet_length());

	uint32_t roc = (packet.get_srtp_index() >> 32);
	ByteVector roc_bytes(sizeof(roc));
	std::generate_n(roc_bytes.begin(), sizeof(roc), LittleEndianToBytes(roc));
	auth.append(roc_bytes);

	// Append auth tag after payload. 
	// This assumes there is enough space in the buffer to append tag_len bytes after end of payload
	auto digest = auth.get_digest();
	std::copy(digest.begin(), digest.begin() + tag_len, packet.get_tag_start());
}

bool SrtpHmacSha1::check(SrtpPacket& packet)
{
	// Authenticated portion:
	// Header || Encrypted Payload || ROC
	auth.append(packet.get_header_start(), packet.get_header_length() + packet.get_payload_length());

	uint32_t roc = (packet.get_srtp_index() >> 32);
	ByteVector roc_bytes(sizeof(roc));
	std::generate_n(roc_bytes.begin(), sizeof(roc), LittleEndianToBytes(roc));
	auth.append(roc_bytes);

	// Append auth tag after payload. 
	// This assumes there is enough space in the buffer to append tag_len bytes after end of payload
	auto digest = auth.get_digest();
	return std::equal(digest.begin(), digest.begin() + tag_len, packet.get_tag_start());
}
