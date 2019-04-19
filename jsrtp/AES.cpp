#include "AES.h"
#include <iostream>
#include "container_slice.h"

namespace AES
{
	namespace sbox
	{
		size_t get_row(uint8_t in)
		{
			return (in & 0xF0) >> 4;
		}

		size_t get_column(uint8_t in)
		{
			return in & 0x0F;
		}

		uint8_t substitute(uint8_t in)
		{
			static std::array<std::array<uint8_t, 16>, 16> box = { {
				{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
				{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
				{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
				{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
				{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
				{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
				{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
				{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
				{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
				{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
				{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
				{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
				{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
				{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
				{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
				{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
				} };

			return box[get_row(in)][get_column(in)];
		}

		uint8_t inverse_substitute(uint8_t in)
		{
			static std::array<std::array<uint8_t, 16>, 16> invertex_box = { {
				{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
				{0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
				{0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
				{0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},	
				{0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
				{0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
				{0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
				{0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
				{0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
				{0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
				{0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
				{0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
				{0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
				{0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
				{0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
				{0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
				} };

			return invertex_box[get_row(in)][get_column(in)];
		}
	}

	void KeySchedule::set_key(std::vector<uint8_t> in_key)
	{
		key = std::move(in_key);
		derive_key_schedule();
	}

	std::vector<uint8_t>::const_iterator KeySchedule::get_round_key(int round)
	{
		if (round >= rounds)
		{
			throw std::invalid_argument("Invalid round");
		}

		return expanded_keys.cbegin() + round * block_size;
	}

	std::vector<uint8_t>::const_iterator KeySchedule::get_expanded_key_word(int i)
	{
		return expanded_keys.cbegin() + i * word_size;
	}

	void KeySchedule::derive_key_schedule()
	{
		rounds = get_nr_rounds(key.size());
		int N = key.size() / word_size;
		expanded_keys.resize(rounds * block_size);

		for (int i = 0; i < rounds * word_size; i++)
		{
			auto word_i = expanded_keys.begin() + i * word_size;
			if (i < N)
			{
				std::copy(key.begin() + i * word_size, key.begin() + i * word_size + word_size, word_i);
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
	word KeySchedule::substitute_word(iter to_substitute)
	{
		word out;
		for (int i = 0; i < word_size; i++)
		{
			out[i] = sbox::substitute(to_substitute[i]);
		}

		return out;
	}

	template<class iter>
	void KeySchedule::rotate_word(iter to_rotate)
	{
		word tmp;

		for (int i = 0; i < word_size; i++)
		{
			tmp[i] = to_rotate[i];
		}


		to_rotate[0] = tmp[1];
		to_rotate[1] = tmp[2];
		to_rotate[2] = tmp[3];
		to_rotate[3] = tmp[0];

	}

	word KeySchedule::get_roundc(unsigned int i)
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
	void KeySchedule::xor_word(iter_out out, iter_in1 in1, iter_in2 in2)
	{
		for (int i = 0; i < word_size; i++)
		{
			out[i] = in1[i] ^ in2[i];
		}
	}

	int get_nr_rounds(std::size_t length)
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

	void AES::set_key(std::vector<uint8_t> key)
	{
		rounds = get_nr_rounds(key.size());
		schedule.set_key(std::move(key));
	}

	std::vector<uint8_t> AES::encrypt(std::vector<uint8_t> plain_text)
	{
		if (plain_text.size() % block_size != 0)
		{
			throw std::invalid_argument("Invalid block length");
		}


		std::vector<uint8_t> cipher_text(plain_text.size());
		int blocks = plain_text.size() / block_size;

		for (int block_ind = 0; block_ind < blocks; ++block_ind)
		{
			auto block = cipher_text.begin() + block_ind * block_size;
			std::copy(plain_text.begin() + block_ind * block_size,
				plain_text.begin() + block_ind * block_size + block_size,
				block);

			encrypt_block(block);
		}

		return cipher_text;
	}

	void AES::encrypt_block(std::vector<uint8_t>::iterator block)
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

	void AES::add_key(std::vector<uint8_t>::iterator block, std::vector<uint8_t>::const_iterator key)
	{
		for (int i = 0; i < block_size; i++)
		{
			block[i] ^= key[i];
		}
	}

	void AES::sub_bytes(std::vector<uint8_t>::iterator block)
	{
		for (int i = 0; i < block_size; i++)
		{
			block[i] = sbox::substitute(block[i]);
		}
	}

	void AES::shift_rows(std::vector<uint8_t>::iterator block)
	{
		for (int i = 1; i < word_size; i++)
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

	void AES::mix_columns(std::vector<uint8_t>::iterator block)
	{
		state mixed;
		static std::array<std::array<uint8_t, 4>, 4> mat = { {
			{ 0x2, 0x3, 0x1, 0x1 },
			{ 0x1, 0x2, 0x3, 0x1 },
			{ 0x1, 0x1, 0x2, 0x3 },
			{ 0x3, 0x1, 0x1, 0x2 } 
			} };

		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				mixed[get_index(i, j)] =
					mul(block[get_index(i, 0)], mat[j][0]) ^
					mul(block[get_index(i, 1)], mat[j][1]) ^
					mul(block[get_index(i, 2)], mat[j][2]) ^
					mul(block[get_index(i, 3)], mat[j][3]);
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
		return i * word_size + j;
	}

	std::vector<uint8_t> AES::decrypt(std::vector<uint8_t> cipher_text)
	{
		if (cipher_text.size() % block_size != 0)
		{
			throw std::invalid_argument("Invalid block length");
		}

		std::vector<uint8_t> plain_text(cipher_text.size());
		int blocks = cipher_text.size() / block_size;

		for (int block_ind = 0; block_ind < blocks; ++block_ind)
		{
			auto block = plain_text.begin() + block_ind * block_size;
			std::copy(cipher_text.begin() + block_ind * block_size,
					  cipher_text.begin() + block_ind * block_size + block_size,
					  block);

			decrypt_block(block);
		}

		return plain_text;
	}

	void AES::decrypt_block(std::vector<uint8_t>::iterator block)
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

	void AES::inverse_sub_bytes(std::vector<uint8_t>::iterator block)
	{
		for (int i = 0; i < block_size; i++)
		{
			block[i] = sbox::inverse_substitute(block[i]);
		}
	}

	void AES::inverse_shift_rows(std::vector<uint8_t>::iterator block)
	{
		for (int i = 1; i < word_size; i++)
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

	void AES::inverse_mix_columns(std::vector<uint8_t>::iterator block)
	{
		state mixed;
		static std::array<std::array<uint8_t, 4>, 4> mat = { {
			{ 0xE, 0xB, 0xD, 0x9 },
			{ 0x9, 0xE, 0xB, 0xD },
			{ 0xD, 0x9, 0xE, 0xB },
			{ 0xB, 0xD, 0x9, 0xE }
			} };

		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				mixed[get_index(i, j)] = 
					mul(block[get_index(i, 0)], mat[j][0]) ^
					mul(block[get_index(i, 1)], mat[j][1]) ^
					mul(block[get_index(i, 2)], mat[j][2]) ^
					mul(block[get_index(i, 3)], mat[j][3]);
			}
		}
		std::copy(mixed.begin(), mixed.end(), block);
	}
}

