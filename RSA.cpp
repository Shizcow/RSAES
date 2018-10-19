#include <gmpxx.h>
#include <limits>
#include <iostream>
#include <stdexcept>
#include <random>
#include <string>
#include <vector>
#include <cassert>
#include <array>
#include <cstdint>

namespace ENC{
  static const std::string base64_chars = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

  static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
  }

  std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) { // Credit to René Nyffenegger
    std::string ret;
    int i = 0, j=0;
    unsigned char char_array_3[3], char_array_4[4];

    while (in_len--) {
      char_array_3[i++] = *(bytes_to_encode++);
      if (i == 3) {
	char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
	char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
	char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
	char_array_4[3] = char_array_3[2] & 0x3f;

	for(i = 0; (i <4) ; i++)
	  ret += base64_chars[char_array_4[i]];
	i = 0;
      }
    }

    if (i){
      for(j = i; j < 3; j++)
	char_array_3[j] = '\0';

      char_array_4[0] = ( char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

      for (j = 0; (j < i + 1); j++)
	ret += base64_chars[char_array_4[j]];

      while((i++ < 3))
	ret += '=';
    }
    return ret;
  }

  std::string base64_decode(std::string const& encoded_string) { // Credit to René Nyffenegger
    std::string ret;
    int in_len = encoded_string.size(), i = 0, j = 0, in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];

    while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
      char_array_4[i++] = encoded_string[in_]; in_++;
      if (i ==4){
	for (i = 0; i <4; i++)
	  char_array_4[i] = base64_chars.find(char_array_4[i]);
	
	char_array_3[0] = ( char_array_4[0] << 2       ) + ((char_array_4[1] & 0x30) >> 4);
	char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
	char_array_3[2] = ((char_array_4[2] & 0x3) << 6) +   char_array_4[3];
	
	for (i = 0; (i < 3); i++)
	  ret += char_array_3[i];
	i = 0;
      }
    }
    
    if (i){
      for (j = 0; j < i; j++)
	char_array_4[j] = base64_chars.find(char_array_4[j]);
      
      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
 
      for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
    }
    return ret;
  }

  namespace RSA{
    std::string packKey(std::pair<mpz_class,mpz_class> key){
      size_t padding = mpz_sizeinbase(key.first.get_mpz_t(), 2); // bits
      padding = padding/8+(padding%8>0?1:0);
      unsigned char *str = (unsigned char*)malloc(padding);
      mpz_export(str, nullptr, 1, 1, 1, 0, key.first.get_mpz_t());
      std::string first = base64_encode(str, padding);
      free(str);
    
      padding = mpz_sizeinbase(key.second.get_mpz_t(), 2); // bits
      padding = padding/8+(padding%8>0?1:0);
      str = (unsigned char*)malloc(padding);
      mpz_export(str, nullptr, 1, 1, 1, 0, key.second.get_mpz_t());
      std::string second = base64_encode(str, padding);
      free(str);
    
      return first+'_'+second;
    };

    std::pair<mpz_class,mpz_class> *unpackKey(std::string key){
      std::string first = key.substr(0, key.find('_'));
      key.erase(0, first.length()+1);
      first = base64_decode(first);
      std::string second = base64_decode(key);
    
      mpz_class _first;
      mpz_import(_first.get_mpz_t(), first.length(), 1, 1, 1, 0, first.c_str());
      mpz_class _second;
      mpz_import(_second.get_mpz_t(), second.length(), 1, 1, 1, 0, second.c_str());
    
      return new std::pair<mpz_class,mpz_class>(_first,_second);
    }
  
    std::string encrypt(std::string input, std::pair<mpz_class,mpz_class> *key){
      size_t padding = mpz_sizeinbase(key->first.get_mpz_t(), 2)/8-1; // pad message
      mpz_class ret;
      if(input.length()>=padding)
	throw std::invalid_argument("message too large!");
      std::string rands;
      gmp_randclass rr(gmp_randinit_default);
      rr.seed(rand());
      for(int i=0; i<padding-input.length()-1; ++i){
	ret = rr.get_z_bits(sizeof(char)*8)+1;
	rands+=(char)' ';//ret.get_ui(); // yes, I'm aware this is lazy
      }

      padding = mpz_sizeinbase(key->first.get_mpz_t(), 2)/8-1;
      mpz_import(ret.get_mpz_t(), padding, 1, 1, 1, 0, (input+'\0'+rands).c_str()); // convert to num
    
      mpz_powm(ret.get_mpz_t(), ret.get_mpz_t(), key->second.get_mpz_t(), key->first.get_mpz_t()); // encrypt

      padding = mpz_sizeinbase(ret.get_mpz_t(), 2); // convert to base 64
      unsigned char *str = (unsigned char*)malloc(padding);
      mpz_export(str, nullptr, 1, 1, 1, 0, ret.get_mpz_t());
      std::string ret_str = base64_encode(str, padding/8+(padding%8>0?1:0));
      free(str);
      return ret_str;
    }

  
    class RSAmanager{
    public:
      std::pair<mpz_class,mpz_class> public_key;
      
      std::string decrypt(std::string msg){
	return fromInt(decode(unzip(msg)));
      }

      RSAmanager(unsigned int bits) : r(gmp_randinit_default){
	r.seed(rand());
	mpz_class p = randPrime(bits);
	mpz_class q = randPrime(bits);
	mpz_class n = p*q;
	mpz_class T = (p-1)*(q-1);
    
	mpz_class ran;
	mpz_class gcd;
	mpz_class e;
	do{
	  e = r.get_z_range(USHRT_MAX)+USHRT_MAX; // Slightly more secure but terrible performance. Doesn't really matter though because we only do this once
	  mpz_gcd(gcd.get_mpz_t(), T.get_mpz_t(), e.get_mpz_t()); // check if coprime
	} while(gcd!=1);

	mpz_class d = modInv(e, T);

	public_key.first = n;
	public_key.second = e;
	private_key = d;
      }
      ~RSAmanager(){ // clear ram just in case
	public_key.first = r.get_z_bits(mpz_sizeinbase(public_key.first.get_mpz_t(), 256)*8); // round up to byte
	public_key.second = r.get_z_bits(mpz_sizeinbase(public_key.second.get_mpz_t(), 256)*8);
	private_key = r.get_z_bits(mpz_sizeinbase(private_key.get_mpz_t(), 256)*8);
	r.seed(0);
      }
      
    private:
      gmp_randclass r;
      mpz_class private_key;
  
      std::string fromInt(mpz_class input){
	char *str = (char*)malloc(mpz_sizeinbase(public_key.first.get_mpz_t(), 2));
	mpz_export(str, nullptr, 1, 1, 1, 0, input.get_mpz_t());
	std::string ret = str;
	free(str);
	return ret;
      }
      
      mpz_class randPrime(unsigned int bits){
	mpz_class ran;
	bool found;
      top:
	found = true;
	ran = r.get_z_bits(bits);
	if(!mpz_probab_prime_p(ran.get_mpz_t(), 100)) // muler-rabbin
	  goto top;
    
	return ran;
      }
      mpz_class modInv(mpz_class a, mpz_class m){
	mpz_class m0 = m;
	mpz_class y = 0, x = 1;

	if (m == 1) 
	  return 0;
    
	mpz_class q, t;
	while (a > 1){ 
	  q = a / m; 
	  t = m; 
	  m = a % m, a = t;
	  t = y; 
	  y = x - q * y; 
	  x = t; 
	} 
	if (x < 0) 
	  x += m0; 
  
	return x; 
      }
  
      mpz_class unzip(std::string input){
	size_t padding = mpz_sizeinbase(public_key.first.get_mpz_t(), 2);
	std::string dec = base64_decode(input);
	mpz_class ret;
	mpz_import(ret.get_mpz_t(), dec.length(), 1, 1, 1, 0, dec.c_str());
	return ret;
      }

      mpz_class decode(mpz_class c){
	mpz_class m;
	mpz_powm(m.get_mpz_t(), c.get_mpz_t(), private_key.get_mpz_t(), public_key.first.get_mpz_t());
	return m;
      }
    };
  }

  namespace AES{
    unsigned char (&rotate(unsigned char (&word)[4]))[4]{
      unsigned char tmp = word[0];
      word[0] = word[1];
      word[1] = word[2];
      word[2] = word[3];
      word[3] = tmp;
      return word;
    }
  
    /* Calculate the rcon used in key expansion */
    unsigned char rcon(unsigned char in) {
      if(in == 0)  
	return 0; 
      unsigned char c=1;
      while(in--!=1)
	if(c&0x80 == 0x80)
	  (c<<=1)^=0x1b;
      return c;
    }

    unsigned char stable[256] = {99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 
				 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 
				 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 
				 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 
				 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 
				 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 
				 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 
				 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 
				 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 
				 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 
				 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 
				 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 
				 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 
				 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 
				 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 
				 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22};

    unsigned char stable_inv[256] = {82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 
				     124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 
				     84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, 
				     8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37, 
				     114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146, 
				     108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132, 
				     144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6, 
				     208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107, 
				     58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115, 
				     150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110, 
				     71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27, 
				     252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244, 
				     31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 
				     96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 
				     160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, 
				     23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125};
  
    static inline unsigned char sbox(unsigned char in){
      return stable[in];
    }
		   
    static inline unsigned char sbox_inv(unsigned char in){
      return stable_inv[in];
    }

    /* This is the core key expansion, which, given a 4-byte value,
     * does some scrambling */
    unsigned char (&schedule_core(unsigned char (&in)[4], unsigned char i))[4]{
      char a;
      /* Rotate the input 8 bits to the left */
      rotate(in);
      /* Apply Rijndael's s-box on all 4 bytes */
      for(a = 0; a < 4; a++) 
	in[a] = sbox(in[a]);
      /* On just the first byte, add 2^i to the byte */
      in[0] ^= rcon(i);
      return in;
    }

    unsigned char (&addRoundKey(unsigned char (&in)[4][4], std::array<unsigned char, 16> key))[4][4]{
      for(char i=0; i<4; ++i)
	for(char j=0; j<4; ++j)
	  in[i][j]^=key[4*i+j];
      return in;
    }

    unsigned char (&shiftrows(unsigned char (&rows)[4][4]))[4][4]{ // reference for slight speed boost
      unsigned char tmp = rows[1][0];
      rows[1][0] = rows[1][1];
      rows[1][1] = rows[1][2];
      rows[1][2] = rows[1][3];
      rows[1][3] = tmp; // shift second row once

      tmp = rows[2][0];
      rows[2][0] = rows[2][2];
      rows[2][2] = tmp;
      tmp = rows[2][1];
      rows[2][1] = rows[2][3];
      rows[2][3] = tmp; // shift third row twice

      tmp = rows[3][0];
      rows[3][0] = rows[3][3];
      rows[3][3] = rows[3][2];
      rows[3][2] = rows[3][1];
      rows[3][1] = tmp; // shift the fourth row thrice

      return rows;
    }
    unsigned char (&unshiftrows(unsigned char (&rows)[4][4]))[4][4]{ // reference for slight speed boost
      unsigned char tmp = rows[1][0];
      rows[1][0] = rows[1][3];
      rows[1][3] = rows[1][2];
      rows[1][2] = rows[1][1];
      rows[1][1] = tmp; // shift second row once

      tmp = rows[2][0];
      rows[2][0] = rows[2][2];
      rows[2][2] = tmp;
      tmp = rows[2][1];
      rows[2][1] = rows[2][3];
      rows[2][3] = tmp; // shift third row twice

      tmp = rows[3][0];
      rows[3][0] = rows[3][1];
      rows[3][1] = rows[3][2];
      rows[3][2] = rows[3][3];
      rows[3][3] = tmp; // shift the fourth row thrice

      return rows;
    }

  
    unsigned char (&subBytes_encrypt(unsigned char (&rows)[4][4]))[4][4]{
      for(auto &row: rows)
	for(auto &elem: row)
	  elem = sbox(elem);
      return rows;
    }
  
    unsigned char (&subBytes_decrypt(unsigned char (&rows)[4][4]))[4][4]{
      for(auto &row: rows)
	for(auto &elem: row)
	  elem = sbox_inv(elem);
      return rows;
    }

    unsigned char ltable[256] = {
				 0x00, 0xff, 0xc8, 0x08, 0x91, 0x10, 0xd0, 0x36, 
				 0x5a, 0x3e, 0xd8, 0x43, 0x99, 0x77, 0xfe, 0x18, 
				 0x23, 0x20, 0x07, 0x70, 0xa1, 0x6c, 0x0c, 0x7f, 
				 0x62, 0x8b, 0x40, 0x46, 0xc7, 0x4b, 0xe0, 0x0e, 
				 0xeb, 0x16, 0xe8, 0xad, 0xcf, 0xcd, 0x39, 0x53, 
				 0x6a, 0x27, 0x35, 0x93, 0xd4, 0x4e, 0x48, 0xc3, 
				 0x2b, 0x79, 0x54, 0x28, 0x09, 0x78, 0x0f, 0x21, 
				 0x90, 0x87, 0x14, 0x2a, 0xa9, 0x9c, 0xd6, 0x74, 
				 0xb4, 0x7c, 0xde, 0xed, 0xb1, 0x86, 0x76, 0xa4, 
				 0x98, 0xe2, 0x96, 0x8f, 0x02, 0x32, 0x1c, 0xc1, 
				 0x33, 0xee, 0xef, 0x81, 0xfd, 0x30, 0x5c, 0x13, 
				 0x9d, 0x29, 0x17, 0xc4, 0x11, 0x44, 0x8c, 0x80, 
				 0xf3, 0x73, 0x42, 0x1e, 0x1d, 0xb5, 0xf0, 0x12, 
				 0xd1, 0x5b, 0x41, 0xa2, 0xd7, 0x2c, 0xe9, 0xd5, 
				 0x59, 0xcb, 0x50, 0xa8, 0xdc, 0xfc, 0xf2, 0x56, 
				 0x72, 0xa6, 0x65, 0x2f, 0x9f, 0x9b, 0x3d, 0xba, 
				 0x7d, 0xc2, 0x45, 0x82, 0xa7, 0x57, 0xb6, 0xa3, 
				 0x7a, 0x75, 0x4f, 0xae, 0x3f, 0x37, 0x6d, 0x47, 
				 0x61, 0xbe, 0xab, 0xd3, 0x5f, 0xb0, 0x58, 0xaf, 
				 0xca, 0x5e, 0xfa, 0x85, 0xe4, 0x4d, 0x8a, 0x05, 
				 0xfb, 0x60, 0xb7, 0x7b, 0xb8, 0x26, 0x4a, 0x67, 
				 0xc6, 0x1a, 0xf8, 0x69, 0x25, 0xb3, 0xdb, 0xbd, 
				 0x66, 0xdd, 0xf1, 0xd2, 0xdf, 0x03, 0x8d, 0x34, 
				 0xd9, 0x92, 0x0d, 0x63, 0x55, 0xaa, 0x49, 0xec, 
				 0xbc, 0x95, 0x3c, 0x84, 0x0b, 0xf5, 0xe6, 0xe7, 
				 0xe5, 0xac, 0x7e, 0x6e, 0xb9, 0xf9, 0xda, 0x8e, 
				 0x9a, 0xc9, 0x24, 0xe1, 0x0a, 0x15, 0x6b, 0x3a, 
				 0xa0, 0x51, 0xf4, 0xea, 0xb2, 0x97, 0x9e, 0x5d, 
				 0x22, 0x88, 0x94, 0xce, 0x19, 0x01, 0x71, 0x4c, 
				 0xa5, 0xe3, 0xc5, 0x31, 0xbb, 0xcc, 0x1f, 0x2d, 
				 0x3b, 0x52, 0x6f, 0xf6, 0x2e, 0x89, 0xf7, 0xc0, 
				 0x68, 0x1b, 0x64, 0x04, 0x06, 0xbf, 0x83, 0x38 };

    unsigned char atable[256] = {
				 0x01, 0xe5, 0x4c, 0xb5, 0xfb, 0x9f, 0xfc, 0x12, 
				 0x03, 0x34, 0xd4, 0xc4, 0x16, 0xba, 0x1f, 0x36, 
				 0x05, 0x5c, 0x67, 0x57, 0x3a, 0xd5, 0x21, 0x5a, 
				 0x0f, 0xe4, 0xa9, 0xf9, 0x4e, 0x64, 0x63, 0xee, 
				 0x11, 0x37, 0xe0, 0x10, 0xd2, 0xac, 0xa5, 0x29, 
				 0x33, 0x59, 0x3b, 0x30, 0x6d, 0xef, 0xf4, 0x7b, 
				 0x55, 0xeb, 0x4d, 0x50, 0xb7, 0x2a, 0x07, 0x8d, 
				 0xff, 0x26, 0xd7, 0xf0, 0xc2, 0x7e, 0x09, 0x8c, 
				 0x1a, 0x6a, 0x62, 0x0b, 0x5d, 0x82, 0x1b, 0x8f, 
				 0x2e, 0xbe, 0xa6, 0x1d, 0xe7, 0x9d, 0x2d, 0x8a, 
				 0x72, 0xd9, 0xf1, 0x27, 0x32, 0xbc, 0x77, 0x85, 
				 0x96, 0x70, 0x08, 0x69, 0x56, 0xdf, 0x99, 0x94, 
				 0xa1, 0x90, 0x18, 0xbb, 0xfa, 0x7a, 0xb0, 0xa7, 
				 0xf8, 0xab, 0x28, 0xd6, 0x15, 0x8e, 0xcb, 0xf2, 
				 0x13, 0xe6, 0x78, 0x61, 0x3f, 0x89, 0x46, 0x0d, 
				 0x35, 0x31, 0x88, 0xa3, 0x41, 0x80, 0xca, 0x17, 
				 0x5f, 0x53, 0x83, 0xfe, 0xc3, 0x9b, 0x45, 0x39, 
				 0xe1, 0xf5, 0x9e, 0x19, 0x5e, 0xb6, 0xcf, 0x4b, 
				 0x38, 0x04, 0xb9, 0x2b, 0xe2, 0xc1, 0x4a, 0xdd, 
				 0x48, 0x0c, 0xd0, 0x7d, 0x3d, 0x58, 0xde, 0x7c, 
				 0xd8, 0x14, 0x6b, 0x87, 0x47, 0xe8, 0x79, 0x84, 
				 0x73, 0x3c, 0xbd, 0x92, 0xc9, 0x23, 0x8b, 0x97, 
				 0x95, 0x44, 0xdc, 0xad, 0x40, 0x65, 0x86, 0xa2, 
				 0xa4, 0xcc, 0x7f, 0xec, 0xc0, 0xaf, 0x91, 0xfd, 
				 0xf7, 0x4f, 0x81, 0x2f, 0x5b, 0xea, 0xa8, 0x1c, 
				 0x02, 0xd1, 0x98, 0x71, 0xed, 0x25, 0xe3, 0x24, 
				 0x06, 0x68, 0xb3, 0x93, 0x2c, 0x6f, 0x3e, 0x6c, 
				 0x0a, 0xb8, 0xce, 0xae, 0x74, 0xb1, 0x42, 0xb4, 
				 0x1e, 0xd3, 0x49, 0xe9, 0x9c, 0xc8, 0xc6, 0xc7, 
				 0x22, 0x6e, 0xdb, 0x20, 0xbf, 0x43, 0x51, 0x52, 
				 0x66, 0xb2, 0x76, 0x60, 0xda, 0xc5, 0xf3, 0xf6, 
				 0xaa, 0xcd, 0x9a, 0xa0, 0x75, 0x54, 0x0e, 0x01 };

    unsigned char gmul(unsigned char a, unsigned char b) {
      unsigned char s = atable[(ltable[a] + ltable[b])%255], q = s, z = 0;
      if(a==0)
	s=z;
      (b==0?s:q)=z;
      return s;
    }

    unsigned char (&mixColumn(unsigned char (&r)[4]))[4] {
      unsigned char a[4], b[4], c, h;
      for (c=0; c<4; c++)
	(b[c] = (a[c]=r[c]) << 1) ^= 0x1B & (unsigned char)((signed char)r[c] >> 7);
      r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
      r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
      r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
      r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
      return r;
    }

    unsigned char (&unmixColumn(unsigned char (&r)[4]))[4] { // this one can't be optimised like mixColumn because the numbers are much larger
      unsigned char a[4];
      memcpy(a, r , 4);
      r[0] = gmul(14,a[0])^gmul(11,a[1])^gmul(13,a[2])^gmul(9,a[3]);
      r[1] = gmul(9,a[0])^gmul(14,a[1])^gmul(11,a[2])^gmul(13,a[3]);
      r[2] = gmul(13,a[0])^gmul(9,a[1])^gmul(14,a[2])^gmul(11,a[3]);
      r[3] = gmul(11,a[0])^gmul(13,a[1])^gmul(9,a[2])^gmul(14,a[3]);
      return r;
    }

    unsigned char (&mixColumns(unsigned char (&in)[4][4]))[4][4] {
      mixColumn(in[0]);
      mixColumn(in[1]);
      mixColumn(in[2]);
      mixColumn(in[3]);
      return in;
    }

    unsigned char (&unmixColumns(unsigned char (&in)[4][4]))[4][4] {
      unmixColumn(in[0]);
      unmixColumn(in[1]);
      unmixColumn(in[2]);
      unmixColumn(in[3]);
      return in;
    }

    std::vector<unsigned char> expand_key(std::vector<unsigned char> in){ // N bit key
      unsigned long long int base_size = in.size(), size_e = base_size*4+112, c = base_size;
      std::vector<unsigned char> out(in); // you can go a little faster with memcpy but I can't seem to get that to work without valgrind yelling at me
      out.resize(base_size*4+113);
    
      unsigned char t[4], i=1, a;
      while(c < size_e) {
	for(a=0; a<4; a++) 
	  t[a] = out[a+c-4];
      
	if(c%base_size==0)
	  schedule_core(t,i++);

	else if(c%base_size%16==0)
	  for(int j = 16; j<base_size; j*=2)
	    if(c%j==0)
	      for(a = 0; a < 4; a++) 
		t[a] = sbox(t[a]);
      
	for(a = 0; a < 4; a++)
	  out[c] = out[c++-base_size]^t[a];

      }
      return out;
    }
  
    struct AESkey{
      std::vector<unsigned char> expanded_key;
      unsigned int idx;
      bool mode; // true = forward, false = backward
      size_t base, size_e;
      AESkey(std::vector<unsigned char> in) : idx(0), mode(true){
	base = in.size();
	size_e = base*4+112;
	expanded_key = expand_key(in);
      }
      AESkey(size_t _base) : idx(0), mode(true){
	base = _base/16; // bits to bytes
	size_e = base*4+112;
	std::vector<unsigned char> vec;
	vec.reserve(base);
	for(int i=0; i<base; ++i)
	  vec.push_back(rand()%254+1); // it doesn't like 0 for some reason
	expanded_key = expand_key(vec);
      }
      ~AESkey(){ // clear ram just in case
	for(auto &e: expanded_key)
	e = rand()%255;
	idx = 0;
	mode = true;
	base = size_e = 0;
      }
      std::array<unsigned char, 16> getRoundKey(bool B = false){
	std::array<unsigned char, 16> ret;
	std::copy_n(expanded_key.begin()+idx*16, 16, ret.begin());
	if(B)advanceRound();
	return ret;
      }
      void advanceRound(){
	if(mode)
	  ++idx;
	else
	  --idx;
      }
      void setStart(){
	idx=0;
	mode = true;
      }
      void setEnd(){
	idx=log2(base)*2+2;
	mode=false;
      }
    };

    unsigned char (&small_encrypt(unsigned char (&in)[4][4], AESkey expanded_key))[4][4]{
      unsigned int N = expanded_key.base;
      expanded_key.setStart();
      addRoundKey(in, expanded_key.getRoundKey(true));
      for(int i=0; i<log2(N)*2+1; ++i){
	subBytes_encrypt(in);
	shiftrows(in);
	mixColumns(in);
	addRoundKey(in, expanded_key.getRoundKey(true));
      }
      subBytes_encrypt(in);
      shiftrows(in);
      addRoundKey(in, expanded_key.getRoundKey(false));
      return in;
    }
    unsigned char (&small_decrypt(unsigned char (&in)[4][4], AESkey expanded_key))[4][4]{
      unsigned int N = expanded_key.base;
      expanded_key.setEnd();
    
      addRoundKey(in, expanded_key.getRoundKey(true));
      unshiftrows(in);
      subBytes_decrypt(in);
    
      for(int i=0; i<log2(N)*2+1; ++i){
	addRoundKey(in, expanded_key.getRoundKey(true));
	unmixColumns(in);
	unshiftrows(in);
	subBytes_decrypt(in);
      }
      addRoundKey(in, expanded_key.getRoundKey(false));
      return in;
    }

    std::string big_encrypt(std::string input, AESkey expanded_key){ // returns as base64
      int size_s = input.length(); // size before padding
      if(size_s==0)
	return "";
      int size_p = size_s % 16; // size after padding
      size_p = size_p==0?size_s:size_s+16-size_p;
      if(size_s!=size_p){ // it needs padding
	input+='\0';
	for(int i=0; i<(size_p-size_s-1); ++i)
	  input+=(char)rand()%255;
      }
      std::string ret;
      const char * c = input.c_str();
      for(int i=0; i<size_p; i+=16){
	unsigned char arr[4][4];
	memcpy(arr, c+i, 16);
	small_encrypt(arr, expanded_key);
	for(auto &row: arr){
	  for(auto &el: row)
	    ret+=(char)el;
	}
      }
      return base64_encode((const unsigned char*)ret.c_str(), size_p);
    }

    std::string big_decrypt(std::string input, AESkey expanded_key){ // returns as string
      input = base64_decode(input);
      int size_s = input.length(); // to strip off after the null we put in
      
      std::string ret;
      const char * c = input.c_str();
      for(int i=0; i<size_s; i+=16){
	unsigned char arr[4][4];
	memcpy(arr, c+i, 16);
	small_decrypt(arr, expanded_key);
	for(auto &row: arr){
	  for(auto &el: row)
	    if(el==0)
	      return ret;
	    else
	      ret+=(char)el;
	}
      }
      return ret;
    }
  }
  
  class EncryptionManager{
    private:
    gmp_randclass rr;
    RSA::RSAmanager* rsaCore;
    AES::AESkey* AES_key;
    std::pair<mpz_class,mpz_class> *unpacked_key;
    
  public:
    EncryptionManager(unsigned int RSAbits): rr(gmp_randinit_default), rsaCore(nullptr), unpacked_key(nullptr), AES_key(nullptr){ // we're sending out the public key
      unsigned int msgLen = RSAbits/8;
      rr.seed(rand());
      rsaCore = new RSA::RSAmanager(RSAbits);
    }
    EncryptionManager(std::string key): rr(gmp_randinit_default), rsaCore(nullptr), unpacked_key(nullptr), AES_key(nullptr){ // we're recieving the public key and generating a pass for AES
      rr.seed(rand());
      unpacked_key = RSA::unpackKey(key);

      size_t AESbits = pow(2,(size_t)log2(mpz_sizeinbase(unpacked_key->first.get_mpz_t(), 2))+1);
      //generate random pass
      AES_key = new AES::AESkey(AESbits);
    }
    EncryptionManager(std::string key, size_t AESbits): rr(gmp_randinit_default), rsaCore(nullptr), unpacked_key(nullptr), AES_key(nullptr){ // specify AES size
      rr.seed(rand());
      unpacked_key = RSA::unpackKey(key);
      AES_key = new AES::AESkey(AESbits);
    }

    ~EncryptionManager(){
      if(rsaCore!=nullptr)
	delete rsaCore;
      if(unpacked_key!=nullptr){
	unpacked_key->first = rr.get_z_bits(mpz_sizeinbase(unpacked_key->first.get_mpz_t(), 256)*8); // clear ram just in case
	unpacked_key->second = rr.get_z_bits(mpz_sizeinbase(unpacked_key->second.get_mpz_t(), 256)*8);
	delete unpacked_key;
      }
      if(AES_key!=nullptr)
	delete AES_key;
      rsaCore=nullptr;
      unpacked_key=nullptr;
      AES_key=nullptr;
    }

    std::string getPublicKey(){
      if(rsaCore==nullptr)
	throw std::runtime_error("This object doesn't have a core attached");
      return RSA::packKey(rsaCore->public_key);
    }

    std::string getKeyResponse(){
      if(AES_key==nullptr)
	throw std::runtime_error("This object hasn't been initilized correctly");
      
      auto p = AES_key->expanded_key.begin();
      std::vector<unsigned char> exp(p, p+AES_key->base); // send the un-expanded key so that we need less data to send
      
      std::string AES_string(exp.begin(), exp.end());
      
      std::string ret = RSA::encrypt(AES_string, unpacked_key);
      unpacked_key->first = rr.get_z_bits(mpz_sizeinbase(unpacked_key->first.get_mpz_t(), 256)*8); // clear ram just in case
      unpacked_key->second = rr.get_z_bits(mpz_sizeinbase(unpacked_key->second.get_mpz_t(), 256)*8);
      delete unpacked_key; // might as well get rid of this
      unpacked_key = nullptr;
      return ret;
    }

    void registerPass(std::string in){
      in = rsaCore->decrypt(in);
      std::vector<unsigned char> exp(in.begin(), in.end());

      AES_key = new AES::AESkey(exp);
      delete rsaCore; // dont need this anymore either
      rsaCore = nullptr;
    }

    std::string encrypt(std::string input){
      if(AES_key==nullptr)
	throw std::runtime_error("Object not properly initialized");
      return AES::big_encrypt(input, *AES_key);
    }

    std::string decrypt(std::string input){
      if(AES_key==nullptr)
	throw std::runtime_error("Object not properly initialized");
      return AES::big_decrypt(input, *AES_key);
    }
  };

  bool EncryptionManagerTest(){
    try{
      std::cout << "Start encryption manager 1 and grab the RSA public key:" << std::endl;
      EncryptionManager Bob(2048);
      std::string msg = Bob.getPublicKey();
      std::cout << msg << std::endl << std::endl;

      std::cout << "Start encryption manager 2, generate a random AES key, and send it back encrypted over RSA:" << std::endl;
      EncryptionManager Allice(msg, 256);
      msg = Allice.getKeyResponse();
      std::cout << msg << std::endl << std::endl;

      std::cout << "Register the AES key with manager 1. Now we can send a message:" << std::endl;
      Bob.registerPass(msg);
      std::string msg_s = "Bepis";
      msg = Bob.encrypt(msg_s);
      std::cout << msg << std::endl << std::endl;

      std::cout << "Now we can decrypt it using manager 2:" << std::endl;
      msg = Allice.decrypt(msg);
      std::cout << msg << std::endl << std::endl;
      assert(msg==msg_s);
  
      std::cout << "Now let's go the other way. Encrypt with manager 2:" << std::endl;
      msg_s = "Bogobepis";
      msg = Allice.encrypt(msg_s);
      std::cout << msg << std::endl << std::endl;

      std::cout << "And decrypt with manager 1:" << std::endl;
      msg = Bob.decrypt(msg);
      std::cout << msg << std::endl << std::endl;
      assert(msg==msg_s);
    } catch (const std::runtime_error& error){
      return false;
    }
    return true;
  }
}

using namespace ENC;
using namespace std;

int main(){
  srand(time(NULL));

  for(int i=0; true; ++i){
    EncryptionManagerTest();
    cout << "-----------------------" << endl;
    cout << "SUCESSFULL TESTS: " << i << endl << endl;
    cout << "-----------------------" << endl;
  }
  
  return 0;
}
