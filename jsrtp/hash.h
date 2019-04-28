#ifndef __HASH__H__
#define __HASH__H__

#include <cstdint>
#include <vector>
#include <array>

template<int d, int b>
class HashFunction
{
public:
	virtual void append(const uint8_t* in, uint64_t len) = 0;
	virtual void append(const std::vector<uint8_t>& in) = 0;
	virtual std::vector<uint8_t> get_digest() = 0;
	virtual ~HashFunction() {}
	static constexpr int DIGEST_SIZE = d;
	static constexpr int BLOCK_SIZE = b;

};

class SHA1 : public HashFunction<20, 64>
{
public:
	virtual void append(const uint8_t* in, uint64_t len);
	virtual void append(const std::vector<uint8_t>& in);
	virtual std::vector<uint8_t> get_digest();

	constexpr static int MESSAGE_LEN_SIZE = 8;
	constexpr static int WORD_SIZE = 32;

private:
	std::vector<uint8_t> message;
	std::array<uint32_t, 80> get_words(std::vector<uint8_t>::iterator chunk_start) const;
	std::vector<uint8_t> preprocess_message() const;

	uint64_t message_len = 0;
	uint32_t left_rotate(uint32_t in, int rotate) const;
};

#endif

