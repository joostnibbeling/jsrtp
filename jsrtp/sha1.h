#ifndef __HASH__H__
#define __HASH__H__

#include <cstdint>
#include <vector>
#include <array>
#include "utils.h"

class SHA1
{
public:
	template<typename Iter>
	void append(Iter in, uint64_t len);
	
	template<typename Container>
	void append(const Container& in);
	
	virtual std::vector<uint8_t> get_digest();

	constexpr static int MESSAGE_LEN_SIZE = 8;
	constexpr static int WORD_SIZE = 32;
	constexpr static int DIGEST_SIZE = 20;
	constexpr static int BLOCK_SIZE = 64;

private:
	std::vector<uint8_t> message;
	std::array<uint32_t, 80> get_words(std::vector<uint8_t>::iterator chunk_start) const;
	std::vector<uint8_t> preprocess_message() const;

	uint64_t message_len = 0;
	uint32_t left_rotate(uint32_t in, int rotate) const;
};

template<typename Iter>
void SHA1::append(Iter in, uint64_t len)
{
	std::copy(in, in + len, std::back_inserter(message));
	message_len += len  * BITS_PER_BYTE;
}

template<typename Container>
void SHA1::append(const Container& in)
{
	std::copy(in.begin(), in.end(), std::back_inserter(message));
	message_len += static_cast<uint64_t>(in.size()) * BITS_PER_BYTE;
}

#endif

