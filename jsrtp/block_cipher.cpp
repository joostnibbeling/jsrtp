#include "block_cipher.h"
#include <iostream>
#include "container_slice.h"

uint8_t AES::sbox_substitute(uint8_t in)
{
	return sbox[sbox_get_row(in)][sbox_get_column(in)];
}

uint8_t AES::sbox_inverse_substitute(uint8_t in)
{
	return invertex_sbox[sbox_get_row(in)][sbox_get_column(in)];
}

uint8_t AES::sbox_get_column(uint8_t in)
{
	return in & 0x0F;
}

uint8_t AES::sbox_get_row(uint8_t in)
{
	return (in & 0xF0) >> 4;
}

void AES::KeySchedule::set_key(ByteVector in_key)
{
	key = std::move(in_key);
	derive_key_schedule();
}

ByteVectorConstIt AES::KeySchedule::get_round_key(int round)
{
	if (round >= rounds)
	{
		throw std::invalid_argument("Invalid round");
	}

	return expanded_keys.cbegin() + round * BLOCK_SIZE;
}

ByteVectorConstIt AES::KeySchedule::get_expanded_key_word(int i)
{
	return expanded_keys.cbegin() + i * WORD_SIZE;
}


void AES::KeySchedule::derive_key_schedule()
{
	rounds = get_nr_rounds(key.size());
	int N = key.size() / WORD_SIZE;
	expanded_keys.resize(rounds * BLOCK_SIZE);

	for (int i = 0; i < rounds * WORD_SIZE; i++)
	{
		auto word_i = expanded_keys.begin() + i * WORD_SIZE;
		if (i < N)
		{
			std::copy(key.begin() + i * WORD_SIZE, key.begin() + i * WORD_SIZE + WORD_SIZE, word_i);
		}
		else if ((i >= N) && (i % N == 0))
		{
			auto word_i_N = get_expanded_key_word(i - N);
			auto word_i_prev = get_expanded_key_word(i - 1);
			auto round_cnst = get_roundc(i / N);

			auto word_perm = substitute_word(word_i_prev);
			substitute_word(word_perm.begin());
			rotate_word(word_perm.begin());
			xor_word(word_i, word_perm.begin(), round_cnst.begin());
			xor_word(word_i, word_i, word_i_N);
		}
		else if ((i >= N) && (N > 6) && (i % N == 4))
		{
			auto word_i_N = get_expanded_key_word(i - N);
			auto word_i_prev = get_expanded_key_word(i - 1);

			auto word_perm = substitute_word(word_i_prev);
			xor_word(word_i, word_i_N, word_perm.begin());
		}
		else
		{
			auto word_i_N = get_expanded_key_word(i - N);
			auto word_i_prev = get_expanded_key_word(i - 1);

			xor_word(word_i, word_i_N, word_i_prev);
		}
	}
}

template<class iter>
AES::word AES::KeySchedule::substitute_word(iter to_substitute)
{
	word out;
	for (int i = 0; i < WORD_SIZE; i++)
	{
		out[i] = AES::sbox_substitute(to_substitute[i]);
	}

	return out;
}

template<class iter>
void AES::KeySchedule::rotate_word(iter to_rotate)
{
	word tmp;

	for (int i = 0; i < WORD_SIZE; i++)
	{
		tmp[i] = to_rotate[i];
	}


	to_rotate[0] = tmp[1];
	to_rotate[1] = tmp[2];
	to_rotate[2] = tmp[3];
	to_rotate[3] = tmp[0];

}

AES::word AES::KeySchedule::get_roundc(unsigned int i)
{
	if (round_constants.size() >= i)
	{
		return { round_constants[i - 1], 0x00, 0x00, 0x00 };
	}

	for (std::size_t j = round_constants.size() + 1; j <= i; ++j)
	{
		uint8_t rc_j;
		uint8_t rc_prev = round_constants[j - 2];

		if (rc_prev < 0x80)
		{
			rc_j = 2 * rc_prev;
		}
		else
		{
			rc_j = static_cast<uint8_t>((2 * rc_prev) | 0x11B);
		}

		round_constants.push_back(rc_j);
	}

	return { round_constants[i - 1], 0x00, 0x00, 0x00 };
}

template<class iter_out, class iter_in1, class iter_in2>
void AES::KeySchedule::xor_word(iter_out out, iter_in1 in1, iter_in2 in2)
{
	for (int i = 0; i < WORD_SIZE; i++)
	{
		out[i] = in1[i] ^ in2[i];
	}
}

int AES::get_nr_rounds(std::size_t length)
{
	switch (length)
	{
	case 16:
		return 11;
		break;
	case 24:
		return 13;
		break;
	case 32:
		return 15;
		break;
	default:
		throw std::invalid_argument("Invalid key size");
	}
}

void AES::set_key(ByteVector key)
{
	rounds = get_nr_rounds(key.size());
	schedule.set_key(std::move(key));
}

ByteVector AES::encrypt(const ByteVector& plain_text)
{
	if (plain_text.size() % BLOCK_SIZE != 0)
	{
		throw std::invalid_argument("Invalid block length");
	}


	ByteVector cipher_text(plain_text.size());
	int blocks = plain_text.size() / BLOCK_SIZE;

	for (int block_ind = 0; block_ind < blocks; ++block_ind)
	{
		auto block = cipher_text.begin() + block_ind * BLOCK_SIZE;
		std::copy(plain_text.begin() + block_ind * BLOCK_SIZE,
			plain_text.begin() + block_ind * BLOCK_SIZE + BLOCK_SIZE,
			block);

		encrypt_block(block);
	}

	return cipher_text;
}

void AES::encrypt_block(ByteVectorIt block)
{
	auto rkey = schedule.get_round_key(0);
	add_key(block, rkey);

	for (int i = 1; i < rounds - 1; ++i)
	{
		sub_bytes(block);
		shift_rows(block);
		mix_columns(block);
		rkey = schedule.get_round_key(i);
		add_key(block, rkey);
	}

	sub_bytes(block);
	shift_rows(block);
	rkey = schedule.get_round_key(rounds - 1);
	add_key(block, rkey);
}

void AES::add_key(ByteVectorIt block, ByteVectorConstIt key)
{
	for (int i = 0; i < BLOCK_SIZE; i++)
	{
		block[i] ^= key[i];
	}
}

void AES::sub_bytes(ByteVectorIt block)
{
	for (int i = 0; i < BLOCK_SIZE; i++)
	{
		block[i] = sbox_substitute(block[i]);
	}
}

void AES::shift_rows(ByteVectorIt block)
{
	for (int i = 1; i < WORD_SIZE; i++)
	{
		word row;

		row[(0 - i) % 4 + ((0 - i) % 4 < 0 ? 4 : 0)] = block[get_index(0, i)];
		row[(1 - i) % 4 + ((1 - i) % 4 < 0 ? 4 : 0)] = block[get_index(1, i)];
		row[(2 - i) % 4 + ((2 - i) % 4 < 0 ? 4 : 0)] = block[get_index(2, i)];
		row[(3 - i) % 4 + ((3 - i) % 4 < 0 ? 4 : 0)] = block[get_index(3, i)];

		block[get_index(0, i)] = row[0];
		block[get_index(1, i)] = row[1];
		block[get_index(2, i)] = row[2];
		block[get_index(3, i)] = row[3];
	}
}

void AES::mix_columns(ByteVectorIt block)
{
	state mixed;
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			mixed[get_index(i, j)] =
				mul(block[get_index(i, 0)], mix_mat[j][0]) ^
				mul(block[get_index(i, 1)], mix_mat[j][1]) ^
				mul(block[get_index(i, 2)], mix_mat[j][2]) ^
				mul(block[get_index(i, 3)], mix_mat[j][3]);
		}
	}

	std::copy(mixed.begin(), mixed.end(), block);
}

uint8_t AES::mul(uint8_t in, uint8_t mul)
{
	switch (mul)
	{
	case 1:
		return mul1(in);
	case 2:
		return mul2(in);
	case 3:
		return mul3(in);
	case 9:
		return mul9(in);
	case 11:
		return mul11(in);
	case 13:
		return mul13(in);
	case 14:
		return mul14(in);
	default:
		throw std::invalid_argument("Invalid multiplicator");
	}

	return 0;
}

uint8_t AES::mul1(uint8_t in)
{
	return in;
}

uint8_t AES::mul2(uint8_t in)
{
	uint8_t out = in << 1;

	if (in & 0x80)
	{
		out ^= 0x1b;
	}

	return out;
}

uint8_t AES::mul3(uint8_t in)
{
	return mul2(in) ^ in;
}

uint8_t AES::mul9(uint8_t in)
{
	return mul2(mul2(mul2(in))) ^ in;
}

uint8_t AES::mul11(uint8_t in)
{
	return mul2(mul2(mul2(in)) ^ in) ^ in;
}

uint8_t  AES::mul13(uint8_t in)
{
	return mul2(mul2(mul2(in) ^ in)) ^ in;
}

uint8_t  AES::mul14(uint8_t in)
{
	return mul2(mul2(mul2(in) ^ in) ^ in);
}

int AES::get_index(int i, int j)
{
	return i * WORD_SIZE + j;
}

ByteVector AES::decrypt(const ByteVector& cipher_text)
{
	if (cipher_text.size() % BLOCK_SIZE != 0)
	{
		throw std::invalid_argument("Invalid block length");
	}

	ByteVector plain_text(cipher_text.size());
	int blocks = cipher_text.size() / BLOCK_SIZE;

	for (int block_ind = 0; block_ind < blocks; ++block_ind)
	{
		auto block = plain_text.begin() + block_ind * BLOCK_SIZE;
		std::copy(cipher_text.begin() + block_ind * BLOCK_SIZE,
					cipher_text.begin() + block_ind * BLOCK_SIZE + BLOCK_SIZE,
					block);

		decrypt_block(block);
	}

	return plain_text;
}

void AES::decrypt_block(ByteVectorIt block)
{
	auto rkey = schedule.get_round_key(rounds - 1);
	add_key(block, rkey);
	inverse_shift_rows(block);
	inverse_sub_bytes(block);

	for(int i = rounds-2; i > 0; --i)
	{
		rkey = schedule.get_round_key(i);
		add_key(block, rkey);
		inverse_mix_columns(block);
		inverse_shift_rows(block);
		inverse_sub_bytes(block);
	}

	rkey = schedule.get_round_key(0);
	add_key(block, rkey);
}

void AES::inverse_sub_bytes(ByteVectorIt block)
{
	for (int i = 0; i < BLOCK_SIZE; i++)
	{
		block[i] = sbox_inverse_substitute(block[i]);
	}
}

void AES::inverse_shift_rows(ByteVectorIt block)
{
	for (int i = 1; i < WORD_SIZE; i++)
	{
		word row;

		row[(0 + i) % 4] = block[get_index(0, i)];
		row[(1 + i) % 4] = block[get_index(1, i)];
		row[(2 + i) % 4] = block[get_index(2, i)];
		row[(3 + i) % 4] = block[get_index(3, i)];

		block[get_index(0, i)] = row[0];
		block[get_index(1, i)] = row[1];
		block[get_index(2, i)] = row[2];
		block[get_index(3, i)] = row[3];
	}
}

void AES::inverse_mix_columns(ByteVectorIt block)
{
	state mixed;

	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			mixed[get_index(i, j)] =
				mul(block[get_index(i, 0)], inverse_mix_mat[j][0]) ^
				mul(block[get_index(i, 1)], inverse_mix_mat[j][1]) ^
				mul(block[get_index(i, 2)], inverse_mix_mat[j][2]) ^
				mul(block[get_index(i, 3)], inverse_mix_mat[j][3]);
		}
	}
	std::copy(mixed.begin(), mixed.end(), block);
}