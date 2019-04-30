#ifndef __HMAC_H__
#define __HMAC_H__
#include <vector>

template <typename HashFunction>
class HMAC
{
public:
	void set_key(std::vector<uint8_t> in_key);

	template<typename Iter>
	void append(const Iter in, uint64_t len);

	template<typename Container>
	void append(const Container& in);

	std::vector<uint8_t> get_digest();
private:
	std::vector<uint8_t> key;
	std::vector<uint8_t> message;
	HashFunction hash_function;
};

template <typename HashFunction>
void HMAC<HashFunction>::set_key(std::vector<uint8_t> in_key)
{
	key = std::move(in_key);
}

template <typename HashFunction>
template<typename Iter>
void HMAC<HashFunction>::append(Iter in, uint64_t len)
{
	std::copy(in, in + len, std::back_inserter(message));
}

template <typename HashFunction>
template<typename Container>
void HMAC<HashFunction>::append(const Container& in)
{
	std::copy(in.begin(), in.end(), std::back_inserter(message));
}

template <typename HashFunction>
std::vector<uint8_t> HMAC<HashFunction>::get_digest()
{
	unsigned int block_size = HashFunction::BLOCK_SIZE;

	if (key.size() > block_size)
	{
		hash_function.append(key);
		key = hash_function.get_digest();
	}

	if (key.size() < block_size)
	{
		int to_pad = block_size - key.size();
		std::fill_n(std::back_inserter(key), to_pad, 0);
	}

	std::vector<uint8_t> o_key_pad(block_size);
	std::transform(key.begin(), key.end(), o_key_pad.begin(), [](uint8_t in) { return in ^ 0x5c; });

	std::vector<uint8_t> i_key_pad(block_size);
	std::transform(key.begin(), key.end(), i_key_pad.begin(), [](uint8_t in) {return in ^ 0x36; });

	hash_function.append(i_key_pad);
	hash_function.append(message);

	message.clear();

	auto inner_digest = hash_function.get_digest();
	hash_function.append(o_key_pad);
	hash_function.append(inner_digest);

	return  hash_function.get_digest();
}

#endif

