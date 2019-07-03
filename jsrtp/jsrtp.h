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
	INVALID_SSRC,
	MASTER_KEY_EXPIRED,
	INVALID_PARAM,
	AUTH_FAIL
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
	ByteVector get_MKI_value();

private:
	int64_t packet_counter = 0;
	ByteVector MKI_value;
	ByteVector master_key;
	ByteVector master_salt;
};

class SrtpStream
{
public:
	class Parameters;

	SrtpStream(const Parameters& params);
	void add_key(unsigned char* key, int key_len);
	void add_key(unsigned char* key, int key_len, unsigned char* MKI, int MKI_len);
	int secure(unsigned char* rtp_packet, int packet_len);
	int unsecure(unsigned char* srtp_packet, int packet_len);

private:
	uint32_t SSRC = 0;
	uint32_t ROC = 0;
	uint16_t s_1 = 0;

	KeyDerivation kdf;

	std::unique_ptr<SrtpCipher> enc_alg;
	std::unique_ptr<SrtpAuth> auth_alg;

	int master_key_len = 16;
	int master_salt_len = 14;

	bool use_MKI = false;
	int MKI_len = 0;

	std::vector<MasterKey> master_keys;
	int active_master_key = -1;
	int determine_rtp_header_size(const RtpHeader& hdr, unsigned char* rtp_packet, int packet_len);
	uint32_t determine_roc(uint16_t seq);
	uint32_t determine_roc_unsecure(uint16_t seq);
	uint64_t determine_srtp_index(const RtpHeader& hdr);
	int get_tag_length();

	uint16_t last_seq;
	bool initial_packet = false;
};

class SrtpStream::Parameters
{
public:
	ENC_ALG cipher = ENC_ALG::AES_CM;
	AUTH_ALG auth = AUTH_ALG::HMAC_SHA1;

	int encryption_key_length = 16;
	int encryption_salt_length = 14;
	int authentication_key_length = 20;
	int authentication_tag_length = 10;
	bool use_MKI = false;
	int MKI_length = 0;
	void set_suite(CRYPTO_SUITE suite);

	uint32_t SSRC = 0;
private:
	int master_key_length = 16;
	int master_salt_length = 14;
	friend class SrtpStream;
};


#endif