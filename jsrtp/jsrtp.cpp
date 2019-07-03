#include "jsrtp.h"

void MasterKey::set_key(unsigned char* key, int length)
{
	master_key.resize(length);
	std::copy(key, key + length, master_key.begin());
}

void MasterKey::set_salt(unsigned char* salt, int length)
{
	master_salt.resize(length);
	std::copy(salt, salt + length, master_salt.begin());
}

void MasterKey::set_mki(unsigned char* mki, int length)
{
	MKI_value.resize(length);
	std::copy(mki, mki + length, MKI_value.begin());
}

ByteVector MasterKey::get_master_key()
{
	return master_key;
}

ByteVector MasterKey::get_master_salt()
{
	return master_salt;
}

void MasterKey::increment_packet_counter()
{
	packet_counter = (packet_counter + 1) % (static_cast<int64_t>(2) << 48);
	if (packet_counter == 0)
	{
		throw SrtpException("Master key has expired", SRTP_ERROR::MASTER_KEY_EXPIRED);
	}
}

ByteVector MasterKey::get_MKI_value()
{
	return MKI_value;
}

SrtpStream::SrtpStream(const Parameters& params)
{
	master_key_len = params.master_key_length;
	master_salt_len = params.master_salt_length;
	use_MKI = params.use_MKI;
	MKI_len = params.MKI_length;
	SSRC = params.SSRC;

	switch (params.cipher)
	{
	case ENC_ALG::AES_CM:
		enc_alg = std::make_unique<SrtpAESCM>(params.encryption_key_length, params.encryption_salt_length);
		break;
	default:
		throw SrtpException("Encryption cipher has not been implemented", SRTP_ERROR::NOT_IMPLEMENTED);
	}

	switch (params.auth)
	{
	case AUTH_ALG::HMAC_SHA1:
		auth_alg = std::make_unique<SrtpHmacSha1>(params.authentication_key_length, params.authentication_tag_length);
		break;
	default:
		throw SrtpException("Authentication method has not been implemented", SRTP_ERROR::NOT_IMPLEMENTED);
	}
}

void SrtpStream::add_key(unsigned char* key, int key_len)
{
	if (use_MKI)
	{
		throw std::invalid_argument("Missing MKI value");
	}

	if (key_len != master_key_len + master_salt_len)
	{
		throw std::invalid_argument("Invalid master key length");
	}

	MasterKey mkey;
	mkey.set_key(key, master_key_len);
	mkey.set_salt(key + master_key_len, master_salt_len);
	master_keys.push_back(std::move(mkey));
}

void SrtpStream::add_key(unsigned char* key, int key_len, unsigned char* MKI, int MKI_len)
{
	if (!use_MKI)
	{
		throw std::invalid_argument("MKI indicator not set");
	}

	if (key_len != master_key_len + master_salt_len)
	{
		throw std::invalid_argument("Invalid master key length");
	}

	if (MKI_len != this->MKI_len)
	{
		throw std::invalid_argument("Invalid MKI length");
	}


	MasterKey mkey;
	mkey.set_key(key, master_key_len);
	mkey.set_salt(key + master_key_len, master_salt_len);
	mkey.set_mki(MKI, MKI_len);
	master_keys.push_back(std::move(mkey));
}

int SrtpStream::secure(unsigned char* rtp_packet, int packet_len)
{
	if (packet_len < 12)
	{
		throw std::invalid_argument("Rtp packet length too small too contain rtp header");
	}

	SrtpPacket packet(rtp_packet, packet_len, false, get_tag_length(), MKI_len);
	
	if (packet.get_ssrc() != SSRC)
	{
		throw SrtpException("SSRC of supplied packet does not match stream SSRC", SRTP_ERROR::INVALID_SSRC);
	}

	uint32_t roc = determine_roc(packet.get_sequence_number());
	uint64_t srtp_index = packet.determine_srtp_index(roc);
	
	bool key_required = enc_alg || auth_alg || use_MKI;

	if (key_required)
	{
		if (master_keys.size() == 0)
		{
			throw SrtpException("No master key has been set", SRTP_ERROR::INVALID_PARAM);
		}

		if (active_master_key == -1)
		{
			active_master_key = 0;
			kdf.set_master_key(master_keys.at(active_master_key).get_master_key());
			kdf.set_master_salt(master_keys.at(active_master_key).get_master_salt());
		}

		master_keys.at(active_master_key).increment_packet_counter();
	}

	if (enc_alg)
	{

		if (kdf.must_derive_key(srtp_index, KeyDerivation::Label::srtp_encryption_key))
		{
			auto key = kdf.derive_key(srtp_index, KeyDerivation::Label::srtp_encryption_key, enc_alg->get_key_length());
			enc_alg->set_key(std::move(key));
		}

		if (kdf.must_derive_key(srtp_index, KeyDerivation::Label::srtp_salting_key))
		{
			auto salt = kdf.derive_key(srtp_index, KeyDerivation::Label::srtp_salting_key, enc_alg->get_salt_length());
			enc_alg->set_salt(std::move(salt));
		}


		enc_alg->encrypt(packet);
	}

	if (auth_alg)
	{

		if (kdf.must_derive_key(srtp_index, KeyDerivation::Label::srtp_authentication_key))
		{
			auto key = kdf.derive_key(srtp_index, KeyDerivation::Label::srtp_authentication_key, auth_alg->get_key_length());
			auth_alg->set_key(std::move(key));
		}

		auth_alg->authenticate(packet);
	}

	if (use_MKI)
	{
		std::copy_n(master_keys.at(active_master_key).get_MKI_value().begin(), MKI_len, packet.get_MKI_start());
	}

	return packet_len + get_tag_length() + MKI_len;
}


int SrtpStream::unsecure(unsigned char* srtp_packet, int packet_len)
{
	if (packet_len < 12 + MKI_len + get_tag_length())
	{
		throw std::invalid_argument("Rtp packet length too small too contain rtp header, mki and tag");
	}

	SrtpPacket packet(srtp_packet, packet_len, true, get_tag_length(), MKI_len);

	if (packet.get_ssrc() != SSRC)
	{
		throw SrtpException("SSRC of supplied packet does not match stream SSRC", SRTP_ERROR::INVALID_SSRC);
	}

	uint32_t roc = determine_roc_unsecure(packet.get_sequence_number());
	uint64_t srtp_index = packet.determine_srtp_index(roc);

	bool key_required = enc_alg || auth_alg || use_MKI;

	if (key_required)
	{
		if (master_keys.size() == 0)
		{
			throw SrtpException("No master key has been set", SRTP_ERROR::INVALID_PARAM);
		}

		if (active_master_key == -1)
		{
			active_master_key = 0;
			kdf.set_master_key(master_keys.at(active_master_key).get_master_key());
			kdf.set_master_salt(master_keys.at(active_master_key).get_master_salt());
		}
	}

	if (auth_alg)
	{
		if (kdf.must_derive_key(srtp_index, KeyDerivation::Label::srtp_authentication_key))
		{
			auto key = kdf.derive_key(srtp_index, KeyDerivation::Label::srtp_authentication_key, auth_alg->get_key_length());
			auth_alg->set_key(std::move(key));
		}

		if (!auth_alg->check(packet))
		{
			throw SrtpException("Could not authenticate packet", SRTP_ERROR::AUTH_FAIL);
		}
	}

	if (enc_alg)
	{

		if (kdf.must_derive_key(srtp_index, KeyDerivation::Label::srtp_encryption_key))
		{
			auto key = kdf.derive_key(srtp_index, KeyDerivation::Label::srtp_encryption_key, enc_alg->get_key_length());
			enc_alg->set_key(std::move(key));
		}

		if (kdf.must_derive_key(srtp_index, KeyDerivation::Label::srtp_salting_key))
		{
			auto salt = kdf.derive_key(srtp_index, KeyDerivation::Label::srtp_salting_key, enc_alg->get_salt_length());
			enc_alg->set_salt(std::move(salt));
		}

		enc_alg->decrypt(packet);
	}

	return packet_len - MKI_len - get_tag_length();
}

int SrtpStream::get_tag_length()
{
	return auth_alg ? auth_alg->get_auth_length() : 0;
}


uint32_t SrtpStream::determine_roc_unsecure(uint16_t seq)
{
	if (!initial_packet)
	{
		s_1 = seq;
		initial_packet = true;
	}

	uint32_t v;

	int32_t s_1s = s_1;
	int64_t ROCs = ROC;
	int32_t seqs = seq;

	if (s_1s < (1 << 15))
	{
		if (seqs - s_1s > (1 << 15))
		{
			v = static_cast<uint32_t>(mod(ROCs - 1, static_cast<int64_t>(1) << 32));
		}
		else
		{
			v = ROC;
			if (seq > s_1) s_1 = seq;
		}
	}
	else
	{
		if (s_1s - (1 << 15) > seqs)
		{
			v = static_cast<uint32_t>(mod(ROCs + 1, static_cast<int64_t>(1) << 32));
			ROC = v;
			s_1 = seq;
		}
		else
		{
			v = ROC;
			if (seq > s_1) s_1 = seq;
		}
	}

	return v;
}

uint32_t SrtpStream::determine_roc(uint16_t seq)
{
	if (!initial_packet)
	{
		last_seq = seq;
		initial_packet = true;
	}
	else
	{
		if (last_seq > seq)
		{
			last_seq = seq;
			ROC++;
		}
	}
	return ROC;
}

uint64_t SrtpStream::determine_srtp_index(const RtpHeader& hdr)
{
	return ( static_cast<uint64_t>(determine_roc(hton(hdr.seq))) << 16) + hton(hdr.seq);
}


int SrtpStream::determine_rtp_header_size(const RtpHeader& hdr, unsigned char* rtp_packet, int packet_len)
{

	if (hdr.version != 2)
	{
		throw std::invalid_argument("Invalid rtp header");
	}

	int header_size = 12 + hdr.cc * 4;

	if (hdr.x)
	{
		if (packet_len < header_size + 4)
		{
			throw std::invalid_argument("Rtp packet length too small too contain rtp header + extension header");
		}

		uint16_t extension_length;
		std::memcpy(&extension_length, rtp_packet + header_size + 2, 2);

		header_size += hton(extension_length);

	}

	if (packet_len < header_size)
	{
		throw std::invalid_argument("Rtp packet length too small too contain rtp header + CSRC");
	}

	return header_size;
}

void SrtpStream::Parameters::set_suite(CRYPTO_SUITE suite)
{
	switch (suite)
	{
	case CRYPTO_SUITE::AES_CM_128_HMAC_SHA1_80:
		// Default, do nothing
		break;
	case CRYPTO_SUITE::AES_CM_128_HMAC_SHA1_32:
		authentication_tag_length = 4;
		break;
	case CRYPTO_SUITE::NULL_CIPHER_HMAC_SHA1_32:
		cipher = ENC_ALG::NULL_CIPHER;
		authentication_tag_length = 4;
		break;
	case CRYPTO_SUITE::NULL_CIPHER_HMAC_SHA1_80:
		cipher = ENC_ALG::NULL_CIPHER;
		break;
	case CRYPTO_SUITE::NULL_CIPHER_NULL_AUTH:
		cipher = ENC_ALG::NULL_CIPHER;
		auth = AUTH_ALG::NULL_AUTH;
		break;
	default:
		throw std::invalid_argument("Crypte Suite not implemented");
	}
}