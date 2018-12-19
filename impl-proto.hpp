#ifndef __RSAES_SOURCE__
#define __RSAES_SOURCE__

//will use mini-gmp or gmp.h, whichever specified during make
#include "SHA256/sha256.h"// hash functions for oaep
#include "SHA256/mgf1.h"  // mask generation for oaep
#include <string>         // passing messages in std::string
#include <vector>         // big key storage
#include <array>          // round key storage
#include <algorithm>      // copy_n (makes cloning vectors faster)
#include <string.h>       // memcpy
#include <math.h>         // pow, log2
#include <openssl/rand.h> // source of random bytes

namespace RSAES{

  namespace UTIL{
  
    const char base64_chars[64] = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
				   'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
				   '.','/','0','1','2','3','4','5','6','7','8','9'};

    inline char find_as_base64(char tofind){
      return static_cast<char>((tofind >= 97) ? // a-z
			       tofind-71
			       :(tofind>=65)? // A-Z
			       tofind-65
			       :tofind+6);     // .-9
    }

    unsigned char* base64_encode(unsigned char const* bytes_to_encode, size_t in_len, size_t* flen){ // Credit to René Nyffenegger, optimized myself
      *flen = (in_len/3*4)+(in_len%3?(in_len%3+1):0);
      unsigned char *ret = (unsigned char*)malloc(sizeof(unsigned char)*(*flen+1));
      size_t ret_idx = 0;
      unsigned char i=0, j=0;
      unsigned char char_array_3[7]; // Apparently this removes one syscall at the cost of using a little more ram
      unsigned char *char_array_4 = char_array_3+3; // "Way" faster - SA

      while (in_len--) {
	char_array_3[i++] = *(bytes_to_encode++);
	if (i == 3) {
	  char_array_4[0] = static_cast<unsigned char>((char_array_3[0] & 0xfc) >> 2);
	  char_array_4[1] = static_cast<unsigned char>(((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4));
	  char_array_4[2] = static_cast<unsigned char>(((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6));
	  char_array_4[3] = static_cast<unsigned char>(char_array_3[2] & 0x3f);

	  for(i = 0; (i <4) ; i++)
	    ret[ret_idx++] = base64_chars[char_array_4[i]];
	  i = 0;
	}
      }

      if (i){
	for(j = i; j < 3; j++)
	  char_array_3[j] = 0;

	char_array_4[0] = static_cast<unsigned char>((char_array_3[0] & 0xfc) >> 2);
	char_array_4[1] = static_cast<unsigned char>(((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4));
	char_array_4[2] = static_cast<unsigned char>(((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6));

	for (j = 0; (j < i + 1); j++)
	  ret[ret_idx++] = base64_chars[char_array_4[j]];
      }
      
      return ret;
    }

    unsigned char* base64_decode(unsigned char const* encoded_string, size_t in_len, size_t* flen) { // Credit to René Nyffenegger, optimized myself
      *flen = in_len/4*3+(in_len%4>1?(in_len%4-1):0);
      unsigned char* ret = (unsigned char*)malloc(sizeof(unsigned char)*(*flen));
      size_t ret_idx = 0;
      unsigned long i = 0, j = 0, in_ = 0;
      unsigned char char_array_3[7]; // See above
      unsigned char *char_array_4 = char_array_3+3;

      while (in_len--){
	char_array_4[i++] = (unsigned char) encoded_string[in_];in_++;
	if (i == 4){
	  for (i = 0; i < 4; i++)
	    char_array_4[i] = static_cast<unsigned char>(find_as_base64(char_array_4[i]));
	
	  char_array_3[0] = static_cast<unsigned char>(( char_array_4[0] << 2       ) + ((char_array_4[1] & 0x30) >> 4));
	  char_array_3[1] = static_cast<unsigned char>(((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2));
	  char_array_3[2] = static_cast<unsigned char>(((char_array_4[2] & 0x3) << 6) + char_array_4[3]);
	
	  for (i = 0; (i < 3); i++)
	    ret[ret_idx++] = char_array_3[i];
	  i = 0;
	}
      }
    
      if (i>1){
	for (j = 0; j < i; j++)
	  char_array_4[j] = static_cast<unsigned char>(find_as_base64(char_array_4[j]));
      
	char_array_3[0] = static_cast<unsigned char>((char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4));
	char_array_3[1] = static_cast<unsigned char>(((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2));
 
	for (j = 0; (j < i - 1); j++) ret[ret_idx++] = char_array_3[j];
      }

      return ret;
    }
  }
  namespace RSA{
    
    std::string packKey(std::pair<mpz_t,mpz_t> const& key){
      size_t padding = mpz_sizeinbase(key.first, 2); // bits
      padding = padding/8+(padding%8>0?1:0);
      unsigned char *str = (unsigned char*)malloc(padding);
      mpz_export(str, nullptr, 1, 1, 1, 0, key.first);
      size_t first_s;
      unsigned char *first = UTIL::base64_encode(str, padding, &first_s);
      free(str);
    
      padding = mpz_sizeinbase(key.second, 2); // bits
      padding = padding/8+(padding%8>0?1:0);
      str = (unsigned char*)malloc(padding);
      mpz_export(str, nullptr, 1, 1, 1, 0, key.second);
      size_t sec_s;
      unsigned char *second = UTIL::base64_encode(str, padding, &sec_s);
      free(str);

      unsigned char* ret = (unsigned char*)malloc(sizeof(unsigned char)*(first_s+1+sec_s)); // TODO: optimize out the memcpys
      memcpy(ret, first, first_s);
      *(ret+first_s)='_';
      memcpy(ret+first_s+1, second, sec_s);
      free(first);
      free(second);

      std::string ret_str;
      ret_str.resize(first_s+1+sec_s);
      memcpy((char*)ret_str.data(), ret, first_s+1+sec_s);
      free(ret);
      
      return ret_str;
    };

    void unpackKey(std::pair<mpz_t,mpz_t> **rop, std::string const& key){
      std::string _first = key.substr(0, key.find('_'));
      std::string _second = key.substr(_first.length()+1, key.length());
      size_t first_s, second_s;
      unsigned char *first = UTIL::base64_decode((const unsigned char*)_first.data(), _first.size(), &first_s);
      unsigned char *second = UTIL::base64_decode((const unsigned char*)_second.data(), _second.size(), &second_s);

      *rop = new std::pair<mpz_t,mpz_t>;
      mpz_init((*rop)->first);
      mpz_import((*rop)->first, first_s, 1, 1, 1, 0, first);
      mpz_init((*rop)->second);
      mpz_import((*rop)->second, second_s, 1, 1, 1, 0, second);
      free(first);
      free(second);
    }
  
    std::string encrypt(std::string const& __input, std::pair<mpz_t,mpz_t> *key){ // TODO: add padding
      std::string input(__input);
      
#define hLen SHA256_DIGEST_LENGTH
      size_t k = (mpz_sizeinbase(key->first, 2)-1)/8+1;
      size_t mLen = input.size();
      if(mLen>k-2*hLen-2)
	throw std::runtime_error("Message too long!");

      unsigned char lHash[SHA256_DIGEST_LENGTH];
      sha256(lHash, "");
      size_t PS_len = k-mLen-2*hLen-2;

      unsigned char seed[SHA256_DIGEST_LENGTH];
      if(RAND_bytes(&seed[0], SHA256_DIGEST_LENGTH)!=1)
	throw std::runtime_error("Openssl rand error");

      unsigned char *EM = (unsigned char*)malloc(sizeof(unsigned char)*k); // combine into one block to save memmoves and syscalls
      EM[0] = 0;

      unsigned char *maskedDB = EM+1+hLen;
      mgf1(maskedDB, seed, SHA256_DIGEST_LENGTH, k-hLen-1); // this part and the left side of the following xors act as dbMask

      size_t i;
      { // all of this inlining is DB in disguize
	for(i=0; i<SHA256_DIGEST_LENGTH; ++i) // doing this cuts out a bunch of unnessicary memcpys and memsets
	  maskedDB[i]^=lHash[i];
	i+=PS_len;
	maskedDB[i]^=0x01;
	++i;
	unsigned char *m = (unsigned char*) input.data();
	for(size_t j=0; j<mLen; ++i,++j)
	  maskedDB[i]^=m[j];
      }
        
      unsigned char *maskedSeed = EM+1;
      mgf1(maskedSeed, maskedDB, k-hLen-1, hLen); // this part and the left size of the following xors act as seedMask
      for(i=0; i<hLen; ++i)
	maskedSeed[i]^=seed[i];

      mpz_t m_c;
      mpz_init(m_c);
      mpz_import(m_c, k, 1, 1, 1, 0, EM);
      free(EM);
	
      mpz_powm(m_c, m_c, key->second, key->first); // encrypt

      size_t size_C = (mpz_sizeinbase(m_c, 2)-1)/8+1;
      unsigned char* C = (unsigned char*)malloc(sizeof(unsigned char*)*k);
      mpz_export(C+(k-size_C), nullptr, 1, 1, 1, 0, m_c);
      mpz_clear(m_c);
      for(i=k-size_C; i-->0;)
	C[i]=0; // fix possible mpz_t missalignment

      size_t ret_s;
      unsigned char *ret_str = UTIL::base64_encode(C, k, &ret_s);
      free(C);

      std::string ret;
      ret.resize(ret_s);
      memcpy((char*)ret.data(), ret_str, ret_s);
      free(ret_str);

      return ret;
#undef hLen
    }

    inline void unzip(mpz_t rop, std::string const& input){
      size_t dec_s;
      unsigned char* dec = UTIL::base64_decode((const unsigned char*)input.data(), input.size(), &dec_s);
      mpz_import(rop, dec_s, 1, 1, 1, 0, dec);
      free(dec);
    }
  
    class RSAmanager{
    public:
      std::pair<mpz_t,mpz_t> public_key;
      
      inline std::string decrypt(std::string const& msg){
	size_t C_s;
	unsigned char *C = UTIL::base64_decode((const unsigned char*)msg.data(), msg.size(), &C_s);
	
#define hLen SHA256_DIGEST_LENGTH
	size_t k = (mpz_sizeinbase(public_key.first, 2)-1)/8+1;
	
	if(k<2*hLen+2||k!=C_s)
	  throw std::runtime_error("Decryption Error");
	
	mpz_t c_m;
	mpz_init(c_m);
	mpz_import(c_m, k, 1, 1, 1, 0, C);
	free(C);

	mpz_powm(c_m, c_m, private_key, public_key.first);

	size_t size_EM = (mpz_sizeinbase(c_m, 2)-1)/8+1;
	unsigned char *EM = (unsigned char*)malloc(sizeof(unsigned char)*k);
        mpz_export(EM+(k-size_EM), nullptr, 1, 1, 1, 0, c_m);
	mpz_clear(c_m);
	for(size_t i=k-size_EM; i-->0;) // will always go once
	  EM[i]=0; // Anything more will fix a possible mpz_t size missalignment

	unsigned char lHash[SHA256_DIGEST_LENGTH];
	sha256(lHash, "");
	
	unsigned char *maskedSeed = &EM[1];    // hLen     bytes long
	unsigned char *maskedDB = &EM[1+hLen]; // k-hLen-1 bytes long

	mgf1_xor(maskedSeed, maskedDB, k-hLen-1, hLen); // from here on out, maskedSeed acts as seed

	mgf1_xor(maskedDB, maskedSeed, hLen, k-hLen-1); // from here on out, maskedDB acts as DB
	
	unsigned char *PS = &maskedDB[SHA256_DIGEST_LENGTH];
	size_t PS_len = 0;
	
	for(unsigned char* ref = PS; !*ref; ++ref)
	  ++PS_len; // counts number of 0x00 bytes
	
	unsigned char *M = &maskedDB[SHA256_DIGEST_LENGTH+PS_len+1]; // (k-hLen-1)-(SHA256_DIGEST_LENGTH+PS_len+1) bytes long
	
	std::string M_str;
	M_str.resize((k-hLen-1)-(SHA256_DIGEST_LENGTH+PS_len+1));
	memcpy((char*)M_str.data(), M, (k-hLen-1)-(SHA256_DIGEST_LENGTH+PS_len+1));
	
	free(EM);
        
	return M_str;
#undef hLen
      }

      RSAmanager(unsigned int bits){
	mpz_init(private_key);
	mpz_init(public_key.first);
	mpz_init(public_key.second);
	gmp_randinit_default(r);
	unsigned long seed;
	if(RAND_bytes((unsigned char*)&seed, sizeof(unsigned long))!=1)
	  throw std::runtime_error("Openssl rand error");
	gmp_randseed_ui(r, seed);
	randPrime(public_key.second, bits);
	mpz_t q;
	mpz_init(q);
	randPrime(q, bits);
	mpz_mul(public_key.first, public_key.second, q);
	//n=p*q;
	mpz_sub_ui(public_key.second, public_key.second, 1);
	mpz_sub_ui(q, q, 1);
	mpz_mul(q, public_key.second, q);
	//T = (p-1)*(q-1);
	do{
	  mpz_urandomb(public_key.second, r, 16);
	  mpz_add_ui(public_key.second, public_key.second, USHRT_MAX); // Slightly more secure but terrible performance. Doesn't really matter though because we only do this once
	  mpz_gcd(private_key, q, public_key.second); // check if coprime
	} while(mpz_cmp_ui(private_key,1)); // gcd!=1
	
	mpz_invert(private_key, public_key.second, q); // Built in is way faster
	mpz_clear(q);
      }
      ~RSAmanager(){ // clear ram just in case
	mpz_urandomb(public_key.first, r, mpz_sizeinbase(public_key.first, 32)); // round up to long (rands all parts)
	mpz_urandomb(public_key.second, r, mpz_sizeinbase(public_key.second, 32));
	mpz_clear(public_key.first);
	mpz_clear(public_key.second);
	mpz_urandomb(private_key, r, mpz_sizeinbase(private_key, 32));
	mpz_clear(private_key);
	gmp_randseed_ui(r, 0);
	gmp_randclear(r); // don't want the seed leaked
      }
      
    private:
      gmp_randstate_t r;
      mpz_t private_key;
      
      inline void randPrime(mpz_t rop, unsigned int bits){ // this is too slow
	do mpz_urandomb(rop, r, bits);
	while(!mpz_probab_prime_p(rop, 100)); // muler-rabbin
      }
    };
  }

  namespace AES{
    void rotate(unsigned char * word){ // shifts array one to the left
      unsigned char tmp = word[0];
      word[0] = word[1];
      word[1] = word[2];
      word[2] = word[3];
      word[3] = tmp;
    }
  
    /* Calculate the rcon used in key expansion */
    unsigned char rcon(unsigned char in) {
      if(in == 0)  
	return 0; 
      unsigned char c=1;
      while(in--!=1)
	if((c&0x80) == 0x80)
	  (c<<=1)^=0x1b;
      return c;
    }

    const unsigned char stable[256]     = {99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 
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

    const unsigned char stable_inv[256] = {82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 
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
  
    inline unsigned char sbox(unsigned char in){
      return stable[in];
    }
		   
    inline unsigned char sbox_inv(unsigned char in){
      return stable_inv[in];
    }

    void schedule_core(unsigned char * in, unsigned char i){
      unsigned char a;
      rotate(in);
      for(a = 0; a < 4; a++) 
	in[a] = sbox(in[a]);
      in[0] ^= rcon(i);
    }

    void addRoundKey(unsigned char * in, std::array<unsigned char, 16> const& key){
      for(unsigned char i=0; i<16; ++i)
	in[i]^=key[i];
    }

    void shiftrows(unsigned char * rows){ // reference for slight speed boost
      unsigned char tmp = rows[1*4+0];
      rows[1*4+0] = rows[1*4+1];
      rows[1*4+1] = rows[1*4+2];
      rows[1*4+2] = rows[1*4+3];
      rows[1*4+3] = tmp; // shift second row once

      tmp = rows[2*4+0];
      rows[2*4+0] = rows[2*4+2];
      rows[2*4+2] = tmp;
      tmp = rows[2*4+1];
      rows[2*4+1] = rows[2*4+3];
      rows[2*4+3] = tmp; // shift third row twice

      tmp = rows[3*4+0];
      rows[3*4+0] = rows[3*4+3];
      rows[3*4+3] = rows[3*4+2];
      rows[3*4+2] = rows[3*4+1];
      rows[3*4+1] = tmp; // shift the fourth row thrice
    }
    void unshiftrows(unsigned char * rows){ // reference for slight speed boost
      unsigned char tmp = rows[4*1+0];
      rows[1*4+0] = rows[1*4+3];
      rows[1*4+3] = rows[1*4+2];
      rows[1*4+2] = rows[1*4+1];
      rows[1*4+1] = tmp; // shift second row once

      tmp = rows[2*4+0];
      rows[2*4+0] = rows[2*4+2];
      rows[2*4+2] = tmp;
      tmp = rows[2*4+1];
      rows[2*4+1] = rows[2*4+3];
      rows[2*4+3] = tmp; // shift third row twice

      tmp = rows[3*4+0];
      rows[3*4+0] = rows[3*4+1];
      rows[3*4+1] = rows[3*4+2];
      rows[3*4+2] = rows[3*4+3];
      rows[3*4+3] = tmp; // shift the fourth row thrice
    }

  
    void subBytes_encrypt(unsigned char * rows){
      for(int i=0; i<16; ++i)
	*(rows+i) = sbox(*(rows+i));
    }
  
    void subBytes_decrypt(unsigned char * rows){
      for(int i=0; i<16; ++i)
	*(rows+i) = sbox_inv(*(rows+i));
    }

    const unsigned char ltable[256] = {0x00, 0xff, 0xc8, 0x08, 0x91, 0x10, 0xd0, 0x36, 
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

    const unsigned char atable[256] = {0x01, 0xe5, 0x4c, 0xb5, 0xfb, 0x9f, 0xfc, 0x12, 
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

    inline unsigned char gmul(unsigned char a, unsigned char b) {
      return static_cast<unsigned char>((!a || !b) ? 0 : atable[(ltable[a] + ltable[b]) % 255]);
    }

    void mixColumn(unsigned char *r) {
      unsigned char a[4], b[4], c;
      for (c=0; c<4; c++)
	(b[c] = (a[c]=r[c]) << 1) ^= 0x1B & (unsigned char)((signed char)r[c] >> 7);
      r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
      r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
      r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
      r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
    }

    void unmixColumn(unsigned char * r) { // this one can't be optimised like mixColumn because the numbers are much larger
      unsigned char a[4];
      memcpy(a, r , 4);
      r[0] = gmul(14,a[0])^gmul(11,a[1])^gmul(13,a[2])^gmul(9,a[3]);
      r[1] = gmul(9,a[0])^gmul(14,a[1])^gmul(11,a[2])^gmul(13,a[3]);
      r[2] = gmul(13,a[0])^gmul(9,a[1])^gmul(14,a[2])^gmul(11,a[3]);
      r[3] = gmul(11,a[0])^gmul(13,a[1])^gmul(9,a[2])^gmul(14,a[3]);
    }

    void mixColumns(unsigned char *in){
      mixColumn(in);
      mixColumn(in+1*4);
      mixColumn(in+2*4);
      mixColumn(in+3*4);
    }

    void unmixColumns(unsigned char *in){
      unmixColumn(in);
      unmixColumn(in+1*4);
      unmixColumn(in+2*4);
      unmixColumn(in+3*4);
    }

    std::vector<unsigned char> expand_key(std::vector<unsigned char> const& in){ // N bit key
      size_t base_size = in.size(), size_e = base_size*4+112, c = base_size;
      std::vector<unsigned char> out;
      out.resize(base_size*4+115);
      memcpy(out.data(), in.data(), base_size);
    
      unsigned char t[4], i=1, a;
      while(c < size_e) {
	for(a=0; a<4; a++) 
	  t[a] = out[a+c-4];
      
	if(c%base_size==0)
	  schedule_core(t,i++);

	else if(!(c%base_size%16))
	  for(size_t j = 16; j<base_size; j*=2)
	    if(!(c%j))
	      for(a = 0; a < 4; a++) 
		t[a] = sbox(t[a]);
      
	for(a = 0; a < 4; a++,c++)
	  out[c] = out[c-base_size]^t[a];

      }
      return out; 
    }
    
    class AESkey{
    private:
      unsigned int idx;
      bool mode; // true = forward, false = backward
    public:
      size_t base;
      std::vector<unsigned char> expanded_key;
      AESkey(std::vector<unsigned char> const& in) : idx(0), mode(true){
	base = in.size();
	expanded_key = expand_key(in);
      }
      AESkey(size_t _base) : idx(0), mode(true){
	base = _base/16; // bits to bytes
	if(base%2)
	  throw std::invalid_argument("bits size is invalid"); //base size should be a multiple of 2
	std::vector<unsigned char> vec;
	vec.resize(base);
	if(RAND_bytes((unsigned char*)vec.data(), base)!=1)
	  throw std::runtime_error("Openssl rand error");
	expanded_key = expand_key(vec);
      }
      ~AESkey(){ // clear ram just in case
	unsigned short *ptr = (unsigned short *)expanded_key.data();
	size_t size = expanded_key.size()/2;
	for(size_t i=0; i<size; ++i, ++ptr)
	  //*ptr = static_cast<unsigned short>(UTIL::dist_short(UTIL::mt));
	  *ptr = 0; // TODO: find a faster way of filling with random data
	idx = 0;
	mode = true;
	base = 0;
      }
      std::array<unsigned char, 16> getRoundKey(bool B = false){
	std::array<unsigned char, 16> ret;
	std::copy_n(expanded_key.begin()+idx*16, 16, ret.begin());
	if(B)advanceRound();
	return ret;
      }
      inline void advanceRound(){
	idx+=mode?1:-1;
      }
      inline void setStart(){
	idx=0;
	mode=true;
      }
      inline void setEnd(){
	idx=static_cast<unsigned int>(log2(base)*2)+2;
	mode=false;
      }
      inline unsigned char* pack(size_t* pack_s){
	return UTIL::base64_encode((unsigned char const*) expanded_key.data(), base, pack_s);
      }
    };

    void small_encrypt(unsigned char * in, AESkey & expanded_key){
      size_t N = expanded_key.base;
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
    }
    void small_decrypt(unsigned char * in, AESkey & expanded_key){
      size_t N = expanded_key.base;
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
    }

    std::string big_encrypt(std::string input, AESkey & expanded_key){ // returns as base64
      size_t size_s = input.length(); // size before padding
      if(size_s==0)
	return "";
      size_t size_p = size_s % 16;
      size_p = size_p==0?size_s:size_s+16-size_p; // size after padding
      if(size_s!=size_p)
	input.resize(size_p);
      
      unsigned char *c = (unsigned char*)input.data();
      if(size_s!=size_p){ // it needs padding
	*(c+size_s) = 0;
	if(RAND_bytes(c+size_s+1, size_p-size_s-1)!=1)
	  throw std::runtime_error("Openssl rand error");
      }
      
      for(size_t i=0; i<size_p/16; i++)
	small_encrypt(c+i*16, expanded_key);

      size_t ret_s;
      unsigned char* ret = UTIL::base64_encode((const unsigned char*)input.c_str(), size_p, &ret_s);
      std::string ret_str;
      ret_str.resize(ret_s);
      memcpy((char*)ret_str.data(), ret, ret_s);
      free(ret);
      
      return ret_str;
    }

    std::string big_decrypt(std::string _input, AESkey & expanded_key){ // returns as string
      size_t input_s;
      unsigned char* c = UTIL::base64_decode((const unsigned char*)_input.data(), _input.size(), &input_s);
      
      for(size_t i=0; i<input_s/16; i++)
	small_decrypt(c+i*16, expanded_key); // no, multithreading does not make this faster
      
      std::string out((char*)c); // this actually just strips the AES padding by ignoring everything after the null char
      free(c);
      return out;
    }
  }
}

#endif // __RSAES_SOURCE__
