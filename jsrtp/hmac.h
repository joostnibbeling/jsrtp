#ifndef __HMAC_H__
#define __HMAC_H__
#include <vector>
#include "hash.h"


class hmac
{
public:
	hmac();
	hmac(std::unique_ptr<HashFunction> in_hash);
	void set_key(std::vector<uint8_t> in_key);
	void append(const uint8_t* in, uint64_t len);
	void append(const std::vector<uint8_t>& in);
	std::vector<uint8_t> get_digest();
private:
	std::vector<uint8_t> key;
	std::vector<uint8_t> message;
	std::unique_ptr<HashFunction> hash = nullptr;
};

#endif

