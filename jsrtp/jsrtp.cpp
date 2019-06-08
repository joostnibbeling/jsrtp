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
	packet_counter = packet_counter++ % (static_cast<int64_t>(2) << 48);
	if (packet_counter == 0)
	{
		throw SrtpException("Master key has expired", SRTP_ERROR::MASTER_KEY_EXPIRED);
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

	rtp_header hdr;
	std::memcpy(&hdr, rtp_packet, sizeof(rtp_header));
	int header_size = determine_rtp_header_size(hdr, rtp_packet, packet_len);
	unsigned char* rtp_payload = rtp_packet + header_size;
	int payload_len = packet_len - header_size;

	uint64_t srtp_index = determine_srtp_index(hdr);

	// TODO: replay check

	if (active_master_key == -1)
	{
		active_master_key = 0;
		kdf.set_master_key(master_keys[active_master_key].get_master_key());
		kdf.set_master_salt(master_keys[active_master_key].get_master_salt());
	}

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

	enc_alg->encrypt(hdr, rtp_payload, payload_len, srtp_index);

	if (kdf.must_derive_key(srtp_index, KeyDerivation::Label::srtp_authentication_key))
	{
		auto key = kdf.derive_key(srtp_index, KeyDerivation::Label::srtp_authentication_key, auth_alg->get_key_length());
		auth_alg->set_key(std::move(key));
	}

	auth_alg->authenticate(hdr, rtp_packet, packet_len, ROC);
	initial_packet = true;

	return packet_len + auth_alg->get_auth_length() + MKI_len;
}

uint32_t SrtpStream::determine_roc(uint16_t seq)
{
	if (!initial_packet)
	{
		last_seq = seq;
	}
	else
	{
		if (last_seq > seq)
		{
			ROC++;
		}
	}
	return ROC;
}

uint64_t SrtpStream::determine_srtp_index(const rtp_header& hdr)
{
	return ( static_cast<uint64_t>(determine_roc(hton(hdr.seq))) << 16) + hton(hdr.seq);
}


int SrtpStream::determine_rtp_header_size(const rtp_header& hdr, unsigned char* rtp_packet, int packet_len)
{

	if (hdr.version != 2)
	{
		throw std::invalid_argument("Invalid rtp header");
	}

	int header_size = 12 + hdr.cc * 4;

	if (packet_len < header_size)
	{
		throw std::invalid_argument("Rtp packet length too small too contain rtp header + CSRC");
	}

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

	return header_size;
}


SrtpStream::Builder& SrtpStream::Builder::set_suite(CRYPTO_SUITE suite)
{
	switch (suite)
	{
	case CRYPTO_SUITE::AES_CM_128_HMAC_SHA1_80:
		// Default, do nothing
		break;
	case CRYPTO_SUITE::AES_CM_128_HMAC_SHA1_32:
		this->set_tag_len(4);
		break;
	case CRYPTO_SUITE::NULL_CIPHER_HMAC_SHA1_32:
		this->set_enc_alg(ENC_ALG::NULL_CIPHER).set_enc_session_key_len(0);
		this->set_tag_len(4);
		break;
	case CRYPTO_SUITE::NULL_CIPHER_HMAC_SHA1_80:
		this->set_enc_alg(ENC_ALG::NULL_CIPHER).set_enc_session_key_len(0);
		break;
	case CRYPTO_SUITE::NULL_CIPHER_NULL_AUTH:
		this->set_enc_alg(ENC_ALG::NULL_CIPHER).set_enc_session_key_len(0);
		this->set_auth_alg(AUTH_ALG::NULL_AUTH).set_auth_session_key_len(0);
		break;
	default:
		throw std::invalid_argument("Crypte Suite not implemented");
	}

	return *this;
}

SrtpStream::Builder& SrtpStream::Builder::set_enc_alg(ENC_ALG enc_alg)
{
	this->enc_alg = enc_alg;
	return *this;
}

SrtpStream::Builder& SrtpStream::Builder::set_auth_alg(AUTH_ALG auth_alg)
{
	this->auth_alg = auth_alg;
	return *this;
}

SrtpStream::Builder& SrtpStream::Builder::set_enc_session_key_len(int key_len)
{
	this->n_e = key_len;
	return *this;
}

SrtpStream::Builder& SrtpStream::Builder::set_auth_session_key_len(int key_len)
{
	this->n_a = key_len;
	return *this;
}

SrtpStream::Builder& SrtpStream::Builder::set_tag_len(int tag_len)
{
	this->tag_len = tag_len;
	return *this;
}

SrtpStream::Builder& SrtpStream::Builder::set_master_salt_len(int master_salt_len)
{
	this->master_salt_len = master_key_len;
	return *this;
}

SrtpStream::Builder& SrtpStream::Builder::set_enc_salt_len(int salt_len)
{
	this->n_s = salt_len;
	return *this;
}

SrtpStream::Builder& SrtpStream::Builder::set_master_key_len(int master_key_len)
{
	this->master_key_len = master_key_len;
	return *this;
}

SrtpStream::Builder& SrtpStream::Builder::set_use_mki(bool use_MKI)
{
	this->use_MKI = use_MKI;
	return *this;
}

SrtpStream::Builder& SrtpStream::Builder::set_mki_len(int MKI_len)
{
	this->MKI_len = MKI_len;
	return *this;
}

SrtpStream* SrtpStream::Builder::build()
{
	auto ctx = new SrtpStream();
	init_context(*ctx);
	return ctx;
}

std::unique_ptr<SrtpStream> SrtpStream::Builder::build_unique()
{
	auto ctx = std::make_unique<SrtpStream>();
	init_context(*ctx);
	return ctx;
}

std::shared_ptr<SrtpStream> SrtpStream::Builder::build_shared()
{
	auto ctx = std::make_shared<SrtpStream>();
	init_context(*ctx);
	return ctx;
}

void SrtpStream::Builder::init_context(SrtpStream& ctx)
{
	ctx.master_key_len = this->master_key_len;
	ctx.master_salt_len = this->master_salt_len;
	ctx.use_MKI = this->use_MKI;
	ctx.MKI_len = this->MKI_len;

	switch (this->enc_alg)
	{
	case ENC_ALG::AES_CM:
		ctx.enc_alg = std::make_unique<SrtpAESCM>(this->n_e, this->n_s);
		break;
	default:
		throw SrtpException("Encryption cipher has not been implemented", SRTP_ERROR::NOT_IMPLEMENTED);
	}

	switch (this->auth_alg)
	{
		case AUTH_ALG::HMAC_SHA1:
			ctx.auth_alg = std::make_unique<SrtpHmacSha1>(this->n_a, this->tag_len);
			break;
		default:
			throw SrtpException("Authentication method has not been implemented", SRTP_ERROR::NOT_IMPLEMENTED);
	}
}
