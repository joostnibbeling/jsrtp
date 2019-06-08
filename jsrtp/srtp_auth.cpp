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

void SrtpHmacSha1::authenticate(const rtp_header& hdr, uint8_t* rtp_packet, int packet_length, uint32_t roc)
{
	auth.append(rtp_packet, packet_length);
	
	ByteVector broc(4);
	std::generate_n(broc.begin(), 4, LittleEndianToBytes(roc));
	auth.append(broc);
	auto digest = auth.get_digest();
	std::copy(digest.begin(), digest.begin() + tag_len, rtp_packet + packet_length);
}
