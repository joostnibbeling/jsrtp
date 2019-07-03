#ifndef __SRTP_CIPHER_H__
#define __SRTP_CIPHER_H__

#include "utils.h"
#include "counter_mode.h"
#include "aes.h"

class SrtpCipher
{
public:
	virtual int get_key_length() = 0;
	virtual int get_salt_length() = 0;
	virtual void set_key(ByteVector key) = 0;
	virtual void set_salt(ByteVector salt) = 0;
	virtual void encrypt(SrtpPacket& packet) = 0;
	virtual void decrypt(SrtpPacket& packet) = 0;
	virtual ~SrtpCipher(){};
};

class SrtpAESCM : public SrtpCipher
{
public:
	SrtpAESCM(int key_len, int salt_len);
	virtual int get_key_length() override;
	virtual int get_salt_length() override;
	virtual void set_key(ByteVector key) override;
	virtual void set_salt(ByteVector salt) override;
	virtual void encrypt(SrtpPacket& packet) override;
	virtual void decrypt(SrtpPacket& packet) override;
private:
	int n_s;
	int n_e;
	CTR<AES> aes;
	ByteVector salt;

};

#endif