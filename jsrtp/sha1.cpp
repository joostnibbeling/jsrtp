#include "sha1.h"
#include <limits>
#include <numeric>
#include <iostream>
#include "utils.h"

std::vector<uint8_t> SHA1::preprocess_message() const
{
	std::vector<uint8_t> preprocessed(message);
	preprocessed.push_back(0x80);

	int to_pad = (BLOCK_SIZE - ((preprocessed.size() + MESSAGE_LEN_SIZE) % BLOCK_SIZE)) % BLOCK_SIZE;
	std::fill_n(std::back_inserter(preprocessed), to_pad, 0x0);
	std::array<uint8_t, 8> len_in;
	std::memcpy(len_in.data(), &message_len, sizeof(message_len));
	std::copy(len_in.rbegin(), len_in.rend(), std::back_inserter(preprocessed));

	return preprocessed;
}

std::array<uint32_t, 80> SHA1::get_words(std::vector<uint8_t>::iterator chunk_start) const
{
	std::array<uint32_t, 80> words;

	for (int i = 0; i < 16; ++i)
	{
		auto toWord = [](uint32_t tot, uint8_t add) {
			return (tot << 8) + add;
		};

		auto start = chunk_start + (i * 4);
		auto end = start + 4;

		words[i] = std::accumulate(start, end, 0, toWord);
	}

	for (int i = 16; i < 80; ++i)
	{
		words[i] = left_rotate(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
	}

	return words;
}

std::vector<uint8_t> SHA1::get_digest()
{
	uint32_t h0 = 0x67452301;
	uint32_t h1 = 0xEFCDAB89;
	uint32_t h2 = 0x98BADCFE;
	uint32_t h3 = 0x10325476;
	uint32_t h4 = 0xC3D2E1F0;

	std::vector<uint8_t> preprocessed = preprocess_message();
	
	for (unsigned int chunk = 0; chunk < preprocessed.size() / BLOCK_SIZE; ++chunk)
	{
		std::array<uint32_t, 80> words = get_words(preprocessed.begin() + (BLOCK_SIZE * chunk));

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

	std::vector<uint8_t> digest(DIGEST_SIZE);

	std::generate(digest.begin(), digest.begin() + 4, make_int_to_bytes(h0));
	std::generate(digest.begin() + 4, digest.begin() + 8, make_int_to_bytes(h1));
	std::generate(digest.begin() + 8, digest.begin() + 12, make_int_to_bytes(h2));
	std::generate(digest.begin() + 12, digest.begin() + 16, make_int_to_bytes(h3));
	std::generate(digest.begin() + 16, digest.begin() + 20, make_int_to_bytes(h4));
	
	message.clear();
	message_len = 0;
	return digest;
}

uint32_t SHA1::left_rotate(uint32_t in, int rotate) const
{
	uint32_t mask = 0xffffffff << (WORD_SIZE - rotate);
	uint32_t left = (in & mask) >> (WORD_SIZE - rotate);
	return (in << rotate) + left;
}