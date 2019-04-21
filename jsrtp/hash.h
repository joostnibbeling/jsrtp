#ifndef __HASH__H__
#define __HASH__H__

#include <cstdint>
#include <vector>
#include <array>

class HashFunction
{
public:
	virtual void append(const uint8_t* in, uint64_t len) = 0;
	virtual void append(const std::vector<uint8_t>& in) = 0;
	virtual std::vector<uint8_t> get_digest() = 0;
	virtual int get_block_size() = 0;
	virtual ~HashFunction() {}

};

class SHA1 : public HashFunction
{
public:
	virtual void append(const uint8_t* in, uint64_t len);
	virtual void append(const std::vector<uint8_t>& in);
	virtual std::vector<uint8_t> get_digest();
	virtual int get_block_size();

	constexpr static int BITS_PER_BYTE = 8;
	constexpr static int MESSAGE_LEN_SIZE = 8;
	constexpr static int DIGEST_SIZE = 20;
	constexpr static int WORD_SIZE = 32;
	constexpr static int BLOCK_SIZE = 64;

private:
	std::vector<uint8_t> message;
	void reverse_copy(std::vector<uint8_t>::iterator out, uint32_t src);
	std::array<uint32_t, 80> get_words(std::vector<uint8_t>::iterator chunk_start);
	std::vector<uint8_t> preprocess_message();

	uint64_t message_len = 0;
	uint32_t left_rotate(uint32_t in, int rotate);
};

#endif

