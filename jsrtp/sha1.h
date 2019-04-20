#ifndef __SHA1__H__
#define __SHA1__H__

#include <cstdint>
#include <vector>
#include <array>

class sha1
{
public:
	constexpr static int digest_size = 20;
	constexpr static int word_size = 32;
	constexpr static int block_size = 64;

	void append(const uint8_t* in, uint64_t len);
	void append(const std::vector<uint8_t>& in);
	std::vector<uint8_t> get_digest();
	int get_digest_size();
	int get_block_size();

private:
	std::vector<uint8_t> message;
	void reverse_copy(std::vector<uint8_t>::iterator out, uint32_t src);

	uint64_t message_len = 0;
	uint32_t left_rotate(uint32_t in, int rotate);
};

#endif

