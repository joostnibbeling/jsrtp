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
		void set_key(std::vector<uint8_t> in_key);
		std::vector<uint8_t>::const_iterator get_round_key(int round);
	private:
		int rounds = 0;
		std::vector<uint8_t> round_constants = { 0x1 };
		std::vector<uint8_t> expanded_keys;
		std::vector<uint8_t> key;

		void derive_key_schedule();
		word get_roundc(unsigned int i);
		
		template<class iter>
		word substitute_word(iter to_substitute);

		template<class iter>
		void rotate_word(iter to_rotate);

		template<class iter_out, class iter_in1, class iter_in2>
		void xor_word(iter_out out, iter_in1 in1, iter_in2 in2);

		std::vector<uint8_t>::const_iterator get_expanded_key_word(int i);
	};
	
	class AES
	{
	public:
		void set_key(std::vector<uint8_t> key);
		std::vector<uint8_t> encrypt(std::vector<uint8_t> plain_text);
		std::vector<uint8_t> decrypt(std::vector<uint8_t> cipher_text);

	private:
		KeySchedule schedule;
		int rounds = 0;
		int get_index(int i, int j);

		void encrypt_block(std::vector<uint8_t>::iterator block);
		void add_key(std::vector<uint8_t>::iterator block, std::vector<uint8_t>::const_iterator key);
		void sub_bytes(std::vector<uint8_t>::iterator block);
		void shift_rows(std::vector<uint8_t>::iterator block);
		void mix_columns(std::vector<uint8_t>::iterator block);


		void decrypt_block(std::vector<uint8_t>::iterator block);
		void inverse_sub_bytes(std::vector<uint8_t>::iterator block);
		void inverse_shift_rows(std::vector<uint8_t>::iterator block);
		void inverse_mix_columns(std::vector<uint8_t>::iterator block);


		uint8_t mul(uint8_t in, uint8_t mul);
		uint8_t mul1(uint8_t in);
		uint8_t mul2(uint8_t in);
		uint8_t mul3(uint8_t in);

		uint8_t mul9(uint8_t in);
		uint8_t mul11(uint8_t in);
		uint8_t mul13(uint8_t in);
		uint8_t mul14(uint8_t in);

	};


}

#endif
