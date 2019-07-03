#ifndef __SRTP_AUTH_H__
#define __SRTP_AUTH_H__

#include "hmac.h"
#include "sha1.h"


class SrtpAuth
{
public:
	virtual ~SrtpAuth() {}
	virtual int get_key_length() = 0;
	virtual int get_auth_length() = 0;
	virtual void set_key(ByteVector key) = 0;
	virtual void authenticate(SrtpPacket& packet) = 0;
	virtual bool check(SrtpPacket& packet) = 0;
};

class SrtpHmacSha1 : public SrtpAuth
{
public:
	SrtpHmacSha1(int key_length, int tag_length);
	virtual int get_key_length() override;
	virtual int get_auth_length() override;
	virtual void set_key(ByteVector key)  override;
	virtual void authenticate(SrtpPacket& packet) override;
	virtual bool check(SrtpPacket& packet) override;

private:
	int tag_len;
	int n_a;
	HMAC<SHA1> auth;
};

#endif

