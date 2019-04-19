#include "sha1.h"
#include <limits>
#include <numeric>
#include <iostream>

void sha1::append(const uint8_t* in, uint64_t len)
{
	if (message_len > std::numeric_limits<uint64_t>::max() - (len*8))
	{
		throw std::runtime_error("Message size is too large");
	}

	std::copy(in, in + len, std::back_inserter(message));
	message_len += len * 8;
}

std::array<uint8_t, sha1::digest_size> sha1::get_digest()
{
	std::vector<uint8_t> preprocessed(message);
	preprocessed.push_back(0x80);

	//int to_pad = 56 - (preprocessed.size() % 56) % 56;
	int to_pad = (64 - ((preprocessed.size() + 8) % 64) ) % 64;
	
	std::fill_n(std::back_inserter(preprocessed), to_pad, 0x0);

	std::array<uint8_t, 8> len_in;
	std::memcpy(len_in.data(), &message_len, sizeof(message_len));
	std::copy(len_in.rbegin(), len_in.rend(), std::back_inserter(preprocessed));

	uint32_t h0 = 0x67452301;
	uint32_t h1 = 0xEFCDAB89;
	uint32_t h2 = 0x98BADCFE;
	uint32_t h3 = 0x10325476;
	uint32_t h4 = 0xC3D2E1F0;

	for (unsigned int chunk = 0; chunk < preprocessed.size() / 64; ++chunk)
	{
		std::array<uint32_t, 80> words;

		for (int i = 0; i < 16; ++i)
		{
			auto little_endian = [](uint32_t tot, uint8_t add) {
				return (tot << 8) + add;
			};

			auto start = preprocessed.begin() + (64 * chunk) + (i * 4);
			auto end = start + 4;

			words[i] = std::accumulate(start, end, 0, little_endian);
		}

		for (int i = 16; i < 80; ++i)
		{
			words[i] = left_rotate(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
		}

		uint32_t a = h0;
		uint32_t b = h1;
		uint32_t c = h2;
		uint32_t d = h3;
		uint32_t e = h4;
		uint32_t k = 0;
		uint32_t f = 0;

		for (int i = 0; i < 80; ++i)
		{
			if (0 <= i && i <= 19)
			{
				f = (b & c) | ((~b) & d);
				k = 0x5A827999;
			}
			else if (20 <= i && i <= 39)
			{
				f = b ^ c ^ d;
				k = 0x6ED9EBA1;
			}
			else if (40 <= i && i <= 59)
			{
				f = (b & c) | (b & d) | (c & d);
				k = 0x8F1BBCDC;
			}
			else if(60 <= i && i <= 79)
			{
				f = b ^ c ^ d;
				k = 0xCA62C1D6;
			}

			uint32_t temp = left_rotate(a, 5) + f + e + k + words[i];
			e = d;
			d = c;
			c = left_rotate(b, 30);
			b = a;
			a = temp;
		}

		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;

	}

	std::array<uint8_t, digest_size> digest {};
	reverse_copy(digest.begin(), h0);
	reverse_copy(digest.begin() + 4, h1);
	reverse_copy(digest.begin() + 8, h2);
	reverse_copy(digest.begin() + 12, h3);
	reverse_copy(digest.begin() + 16, h4);

	return digest;
}

void sha1::reverse_copy(std::array<uint8_t, digest_size>::iterator out, uint32_t src)
{
	out[0] = (src & 0xFF << 24) >> 24;
	out[1] = (src & 0xFF << 16) >> 16;
	out[2] = (src & 0xFF << 8) >> 8;
	out[3] = src & 0xFF;	
}

uint32_t sha1::left_rotate(uint32_t in, int rotate)
{
	uint32_t mask = 0xffffffff << (word_size - rotate);
	uint32_t left = (in & mask) >> (word_size - rotate);
	return (in << rotate) + left;
}
