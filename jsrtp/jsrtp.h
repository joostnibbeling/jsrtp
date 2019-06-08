#ifndef __JSRTP_H__
#define __JSRTP_H__

#include "counter_mode.h"
#include "hmac.h"
#include "sha1.h"
#include "key_derivation.h"
#include "srtp_cipher.h"
#include "srtp_auth.h"

enum class SRTP_ERROR
{
	NOT_IMPLEMENTED,
	MASTER_KEY_EXPIRED
};

class SrtpException : public std::runtime_error
{
public:
	SrtpException(const std::string msg, SRTP_ERROR e) : std::runtime_error(msg), error_code(e) {};
	SRTP_ERROR error_code;
};


enum class CRYPTO_SUITE
{
	NULL_CIPHER_HMAC_SHA1_80,
	NULL_CIPHER_HMAC_SHA1_32,
	NULL_CIPHER_NULL_AUTH,
	AES_CM_128_HMAC_SHA1_80,
	AES_CM_128_HMAC_SHA1_32,
};

enum class ENC_ALG
{
	NULL_CIPHER,
	AES_CM
};

enum class AUTH_ALG
{
	NULL_AUTH,
	HMAC_SHA1
};

class MasterKey
{
public:
	void set_key(unsigned char* key, int length);
	void set_salt(unsigned char* salt, int length);
	void set_mki(unsigned char* mki, int length);
	void increment_packet_counter();

	ByteVector get_master_key();
	ByteVector get_master_salt();

private:
	int64_t packet_counter = 0;
	ByteVector MKI_value;
	ByteVector master_key;
	ByteVector master_salt;
};

class SrtpStream
{
public:
	class Builder;
	
	void add_key(unsigned char* key, int key_len);
	void add_key(unsigned char* key, int key_len, unsigned char* MKI, int MKI_len);

	int secure(unsigned char* rtp_packet, int packet_len);

private:
	uint32_t ROC = 0;
	uint16_t s_1 = 0;

	KeyDerivation kdf;

	std::unique_ptr<SrtpCipher> enc_alg;
	std::unique_ptr<SrtpAuth> auth_alg;

	//std::unique_ptr<CTR<AES>> enc_alg;
	//std::unique_ptr<HMAC<SHA1>> auth_alg;

	int master_key_len = 16;
	int master_salt_len = 14;

	bool use_MKI = false;
	int MKI_len = 0;

	std::vector<MasterKey> master_keys;
	int active_master_key = -1;
	int determine_rtp_header_size(const rtp_header& hdr, unsigned char* rtp_packet, int packet_len);
	uint32_t determine_roc(uint16_t seq);
	uint64_t determine_srtp_index(const rtp_header& hdr);

	uint16_t last_seq;
	bool initial_packet = false;



	/*
	// Encryption session key length
	int n_e = 16;

	// Authentication session key length
	int n_a = 20;

	// Encryption session key salt
	int n_s = 14;

	// Encryption tag length
	int n_tag = 10;
	*/


	friend class Builder;
};

class SrtpStream::Builder
{
public:
	Builder& set_suite(CRYPTO_SUITE suite);
	Builder& set_enc_alg(ENC_ALG enc_alg);
	Builder& set_auth_alg(AUTH_ALG auth_alg);
	Builder& set_enc_session_key_len(int key_len);
	Builder& set_auth_session_key_len(int key_len);
	Builder& set_enc_salt_len(int salt_len);
	Builder& set_tag_len(int tag_len);
	Builder& set_use_mki(bool use_MKI);
	Builder& set_mki_len(int MKI_len);

	SrtpStream* build();
	std::unique_ptr<SrtpStream> build_unique();
	std::shared_ptr<SrtpStream> build_shared();

private:
	Builder& set_master_salt_len(int master_salt_len);
	Builder& set_master_key_len(int master_key_len);

	ENC_ALG enc_alg = ENC_ALG::AES_CM;
	AUTH_ALG auth_alg = AUTH_ALG::HMAC_SHA1;
	int n_e = 16;
	int n_s = 14;
	int n_a = 20;
	int tag_len = 10;
	int master_key_len = 16;
	int master_salt_len = 14;
	bool use_MKI = false;
	int MKI_len = 0;

	void init_context(SrtpStream& ctx);
};


#endif