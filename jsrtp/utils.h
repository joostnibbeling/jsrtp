#ifndef __UTILS_H__
#define __UTILS_H__
#include <vector>
#include <array>
#include <cstdint>

struct rtp_header
{
	uint8_t cc : 4;
	uint8_t x : 1;
	uint8_t p : 1;
	uint8_t version : 2;
	uint8_t pt : 7;
	uint8_t m : 1;
	uint16_t seq;
	uint32_t ts;
	uint32_t ssrc;
};

static_assert(sizeof(rtp_header) == 12, "rtp header size is invalid");

constexpr static int BITS_PER_BYTE = 8;

template<std::size_t N>
using ByteArray = std::array<uint8_t, N>;

template<std::size_t N>
using ByteArrayIt = typename std::array<uint8_t, N>::iterator;

template<std::size_t N>
using ByteArrayConstIt = typename std::array<uint8_t, N>::const_iterator;

using ByteVector = std::vector<uint8_t>;
using ByteVectorIt = typename std::vector<uint8_t>::iterator;
using ByteVectorConstIt = typename std::vector<uint8_t>::const_iterator;

template<typename Integral>
Integral hton(Integral in)
{
	Integral res = 0;
	Integral mask = 0xFF;

	while (in != 0)
	{
		res = (res << BITS_PER_BYTE) + (in & mask);
		in = in >> BITS_PER_BYTE;
	}

	return res;
}

template<typename Intergral, std::size_t bytes>
class LittleEndianToBytesGen
{
public:
	LittleEndianToBytesGen(Intergral in) : little_endian(in), offset(bytes * BITS_PER_BYTE) {}
	uint8_t operator() () {
		offset -= 8;
		if (offset < 0) return 0;
		return (little_endian & 0xFF << offset) >> offset;
	}
private:
	Intergral little_endian;
	int offset;
};

template<typename Integral, std::size_t bytes = sizeof(Integral)>
auto LittleEndianToBytes(Integral in)
{
	return LittleEndianToBytesGen<Integral, bytes>(in);
}

#endif