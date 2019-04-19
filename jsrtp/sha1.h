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
	constexpr static int message_len_size = 64;

	void append(const uint8_t* in, uint64_t len);
	std::array<uint8_t, digest_size> get_digest();
private:
	std::vector<uint8_t> message;
	void reverse_copy(std::array<uint8_t, digest_size>::iterator out, uint32_t src);

	uint64_t message_len = 0;
	uint32_t left_rotate(uint32_t in, int rotate);
};

#endif

