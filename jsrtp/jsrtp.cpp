#include "jsrtp.h"

void MasterKey::set_key(unsigned char* key, int length)
{
	std::vector<uint8_t> vkey(length);
	std::copy(key, key + length, vkey.begin());
	kdf.set_master_key(std::move(vkey));
}

void MasterKey::set_salt(unsigned char* salt, int length)
{
	std::vector<uint8_t> vsalt(length);
	std::copy(salt, salt + length, vsalt.begin());
	kdf.set_master_salt(std::move(vsalt));
}

void MasterKey::set_mki(unsigned char* mki, int length)
{
	MKI_value.reserve(length);
	std::copy(mki, mki + length, std::back_inserter(MKI_value));
}


void SrtpStream::set_suite(CRYPTO_SUITE suite)
{
	switch (suite)
	{
	case CRYPTO_SUITE::AES_CM_128_HMAC_SHA1_80:
		break;
	case CRYPTO_SUITE::AES_CM_128_HMAC_SHA1_32:
		n_tag = 4;
		break;
	}
}

void SrtpStream::set_mki_len(int len)
{
	use_MKI = true;
	MKI_len = len;
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
}
