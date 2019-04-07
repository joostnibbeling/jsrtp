#ifndef __AES_H__
#define __AES_H__

#include<cstdint>
#include<array>
#include<vector>

namespace AES
{
	constexpr static int word_size = 4;
	constexpr static int block_size = 16;

	using word = std::array<uint8_t, word_size>;
	using state = std::array<uint8_t, block_size>;

	int get_nr_rounds(std::size_t);

	namespace sbox
	{
		uint8_t substitute(uint8_t in);
		uint8_t inverse_substitute(uint8_t in);
	}

	class KeySchedule
	{
	public:
		std::vector<uint8_t> key;
		void set_key(std::vector<uint8_t> in_key);
		state get_round_key(int round);
	private:
		std::vector<uint8_t> round_constants = { 0x1 };
		int rounds = 0;
		std::vector<word> partial_keys;
		std::vector<word> expanded_keys;

		void split_key();
		void derive_key_schedule();
		word substitute_word(const word& to_substitute);
		word rotate_word(const word& to_rotate);
		word get_roundc(unsigned int i);
		word xor_word(const word& w1, const word& w2);
	};
	
	class AES
	{
	public:
		void set_key(std::vector<uint8_t> key);
		std::vector<uint8_t> encrypt(std::vector<uint8_t> cipher_text);
		std::vector<uint8_t> decrypt(std::vector<uint8_t> plain_text);
		state encrypt_block(const state& block);
		state add_key(const state& block, const state& rkey);
		state sub_bytes(const state& block);
		state shift_rows(const state& block);
		state mix_columns(const state& block);

		uint8_t mul(uint8_t in, uint8_t mul);
		uint8_t mul1(uint8_t in);
		uint8_t mul2(uint8_t in);
		uint8_t mul3(uint8_t in);

		int get_index(int i, int j);

	private:
		KeySchedule schedule;
		int rounds = 0;
	};


}

#endif
