#ifndef __BLOCK_MODE_H
#define __BLOCK_MODE_H
#include "utils.h"
#include "cipher.h"

class BlockMode
{
public:
	virtual void set_key(ByteVector) = 0;
	virtual void set_iv(ByteVector) = 0;
	virtual ByteVector encrypt(const ByteVector& plaint_text) = 0;
	virtual ByteVector decrypt(const ByteVector& cipher_text) = 0;
	virtual ~BlockMode() {}
};

class CTR : public BlockMode
{

public:
	CTR();
	CTR(std::unique_ptr<Cipher> in_cipher);
	virtual void set_key(ByteVector in_key);
	virtual void set_iv(ByteVector in_iv);
	virtual ByteVector encrypt(const ByteVector& plaint_text);
	virtual ByteVector decrypt(const ByteVector& cipher_text);
private:
	void reset_ctr();
	void increment_ctr();

	std::unique_ptr<Cipher> cipher;
	ByteVector ctr;
};

#endif