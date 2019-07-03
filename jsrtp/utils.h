#ifndef __UTILS_H__
#define __UTILS_H__
#include <vector>
#include <array>
#include <cstdint>

struct RtpHeader
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

	static constexpr int BASE_HEADER_LENGTH = 12;
	static constexpr int CSRC_LENGTH = 4;
	static constexpr int EXTENSION_HEADER_LENGTH = 4;
};

class SrtpPacket
{
public:
	SrtpPacket(uint8_t* packet_start, int packet_length, bool is_secure, int tag_length, int MKI_length);
	uint16_t get_sequence_number() const;
	uint32_t get_ssrc() const;
	uint64_t get_srtp_index() const;
	int get_payload_length() const;
	int get_header_length() const;
	int get_packet_length() const;

	uint8_t* get_payload_start();
	uint8_t* get_header_start();
	uint8_t* get_MKI_start();
	uint8_t* get_tag_start();

	uint64_t determine_srtp_index(uint32_t roc);
private:

	int determine_rtp_header_length();

	int header_length;
	RtpHeader rtp_header;

	int packet_length;
	uint8_t* packet_start;

	int payload_length;
	uint8_t* payload_start;

	static constexpr uint64_t INVALID_SRTP_INDEX = -1;
	uint64_t srtp_index = INVALID_SRTP_INDEX;

	int tag_length;
	uint8_t* tag_start;

	uint8_t* MKI_start;
	int MKI_length;
};

static_assert(sizeof(RtpHeader) == 12, "rtp header size is invalid");

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

template<std::size_t bytes, typename Integral>
auto LittleEndianToBytes(Integral in)
{
	return LittleEndianToBytesGen<Integral, bytes>(in);
}

template<typename Integral>
Integral mod(Integral k, Integral n)
{
	return ((k %= n) < 0) ? k + n : k;
}

#endif