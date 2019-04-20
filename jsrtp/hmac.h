#ifndef __HMAC_H__
#define __HMAC_H__
#include <vector>
#include "sha1.h"


class hmac
{
public:
	void set_key(std::vector<uint8_t> in_key);
	void append(const uint8_t* in, uint64_t len);
	void append(const std::vector<uint8_t>& in);
	std::vector<uint8_t> get_digest();
private:
	std::vector<uint8_t> key;
	std::vector<uint8_t> message;
	sha1 hash;
};

#endif

