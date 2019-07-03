#include "utils.h"

SrtpPacket::SrtpPacket(uint8_t* packet_start, int packet_length, bool is_secure, int tag_length, int MKI_length)
{
	if (packet_length < 12)
	{
		throw std::invalid_argument("Rtp packet length too small too contain rtp header");
	}

	this->packet_start = packet_start;
	this->packet_length = packet_length;
	this->tag_length = tag_length;
	this->MKI_length = MKI_length;
	std::memcpy(&rtp_header, packet_start, sizeof(RtpHeader));

	if (rtp_header.version != 2)
	{
		throw std::invalid_argument("Invalid rtp header");
	}

	header_length = determine_rtp_header_length();


	payload_length = packet_length - header_length;
	
	if (is_secure)
	{
		payload_length -= tag_length - MKI_length; 
	}
	
	payload_start = packet_start + header_length;
	MKI_start = payload_start + payload_length;
	tag_start = MKI_start + MKI_length;
}

int SrtpPacket::determine_rtp_header_length()
{
	int header_length = RtpHeader::BASE_HEADER_LENGTH + rtp_header.cc * RtpHeader::CSRC_LENGTH;

	if (rtp_header.x)
	{
		if (packet_length < header_length + RtpHeader::EXTENSION_HEADER_LENGTH)
		{
			throw std::invalid_argument("Rtp packet length too small too contain rtp header + extension header");
		}

		uint16_t extension_length;
		std::memcpy(&extension_length, packet_start + header_length + 2, 2);
		header_length += hton(extension_length);
	}

	if (packet_length < header_length)
	{
		throw std::invalid_argument("Rtp packet length too small too contain rtp header of indicated size");
	}

	return header_length;
}

uint16_t SrtpPacket::get_sequence_number() const
{
	return hton(rtp_header.seq);
}

uint32_t SrtpPacket::get_ssrc() const
{
	return hton(rtp_header.ssrc);
}

uint64_t SrtpPacket::determine_srtp_index(uint32_t roc)
{
	srtp_index = (static_cast<uint64_t>(roc) << 16) + hton(rtp_header.seq);
	return srtp_index;
}

int SrtpPacket::get_payload_length() const
{
	return payload_length;
}

uint8_t* SrtpPacket::get_MKI_start()
{
	return MKI_start;
}

uint8_t* SrtpPacket::get_tag_start()
{
	return tag_start;
}

uint64_t SrtpPacket::get_srtp_index() const
{
	if (srtp_index == INVALID_SRTP_INDEX)
	{
		throw std::logic_error("Srtp packet index has not been computed yet");
	}

	return srtp_index;
}

int SrtpPacket::get_header_length() const
{
	return header_length;
}

int SrtpPacket::get_packet_length() const
{
	return packet_length;
}

uint8_t* SrtpPacket::get_payload_start()
{
	return payload_start;
}

uint8_t* SrtpPacket::get_header_start()
{
	return packet_start;
}