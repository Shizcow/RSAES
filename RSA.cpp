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


using namespace std;

namespace RSA{
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

  
  struct RSA{
    gmp_randclass r; // maybe TODO: combine these two
    std::pair<mpz_class,mpz_class> public_key;
    
    std::string decrypt(std::string msg){
      return fromInt(decode(unzip(msg)));
    }

    RSA(unsigned int bits) : r(gmp_randinit_default){
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
      
  private:
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

  
  struct EncryptionManager{
    gmp_randclass rr;

    RSA* rsaCore;
    std::string SHA_string;
    std::pair<mpz_class,mpz_class> *unpacked_key; // saves a little ram
    
    EncryptionManager(unsigned int bits): rr(gmp_randinit_default), rsaCore(nullptr), unpacked_key(nullptr){ // we're sending out the public key
      rr.seed(rand());
      rsaCore = new RSA(bits);
    }
    EncryptionManager(std::string key): rr(gmp_randinit_default), rsaCore(nullptr), unpacked_key(nullptr){ // we're recieving the public key and generating a pass for SHA
      rr.seed(rand());
      unpacked_key = unpackKey(key);

      for(int i=0; i<key.length()/2; ++i){
	mpz_class x = rr.get_z_range(94);
	SHA_string+=(char)(x.get_ui()+32); // generate random aplha pass
      }                                    // I tried the full range of chars but that really didnt work 
    }

    ~EncryptionManager(){
      if(rsaCore!=nullptr)
	delete rsaCore;
      if(unpacked_key!=nullptr)
	delete unpacked_key;
    }

    std::string getPublicKey(){
      if(rsaCore==nullptr)
	throw std::invalid_argument("This object doesn't have a core attached");
      return packKey(rsaCore->public_key);
    }

    std::string getKeyResponse(){
      std::string ret = encrypt(SHA_string, unpacked_key);
      delete unpacked_key; // might as well get rid of this
      unpacked_key = nullptr;
      return ret;
    }

    void registerPass(std::string in){
      in = rsaCore->decrypt(in);
      SHA_string = in;
      delete rsaCore; // dont need this anymore either
      rsaCore = nullptr;
    }

  };

  void test(unsigned int bits){

    EncryptionManager Allice(bits);
    
    cout << "First, send the public key:" << endl;
    std::string msg = Allice.getPublicKey();
    cout << msg << endl << endl;
    
    EncryptionManager Bob(msg);
    
    msg = Bob.getKeyResponse();
    
    cout << "Then, send an encrypted response containing a SHA password:" << endl;
    cout << msg << endl << endl;
    
    Allice.registerPass(msg);
    assert(Allice.SHA_string == Bob.SHA_string);
    cout << "Register password on side one. Recieved password is below:" << endl;
    cout << Allice.SHA_string << endl << endl;
  }

  void test(){
    test(256);
  }

  //starting AES stuff

  unsigned char (&shiftrows_encrypt(unsigned char (&rows)[4][4]))[4][4]{ // reference for slight speed boost
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
  unsigned char (&shiftrows_decrypt(unsigned char (&rows)[4][4]))[4][4]{ // reference for slight speed boost
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

  /* Log table using 0xe5 (229) as the generator */
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

  /* Anti-log table: */
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

  static inline unsigned char gmul_inverse(unsigned char in) {
    return in==0?0:atable[(255 - ltable[in])];
  }

  /* Calculate the s-box for a given number */
  unsigned char sbox(unsigned char in) {
    unsigned char c, s, x;
    s = x = gmul_inverse(in);
    for(c = 0; c < 4; c++) {
      /* One bit circular rotate to the left */
      s = (s << 1) | (s >> 7);
      /* xor with x */
      x ^= s;
    }
    x ^= 99; /* 0x63 */
    return x;
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
  
  std::vector<unsigned char> &expand_key_128(std::vector<unsigned char> &in) {
    in.reserve(176);
    unsigned char t[4], c = 16, i = 1, a;

    while(c<176){
      
      for(a=0; a<4; a++) 
	t[a] = in[a+c-4];
      
      if(c%16==0)
	schedule_core(t,i++);
      
      for(a = 0; a<4; a++)
	in[c] = in[c++-16]^t[a];
    }
    return in;
  }

  std::vector<unsigned char> &expand_key_256(std::vector<unsigned char> &in){
    in.reserve(240);
    unsigned char t[4], c=32, i=1, a;
    while(c < 240) {
      
      for(a=0; a<4; a++) 
	t[a] = in[a+c-4];
      
      if(c%32==0)
	schedule_core(t,i++);
      
      if(c%32==16)
	for(a = 0; a < 4; a++) 
	  t[a] = sbox(t[a]);
      
      for(a = 0; a < 4; a++)
	in[c] = in[c++-32]^t[a];
    }
    return in;
  }

  std::vector<unsigned char> &expand_key_512(std::vector<unsigned char> &in){
    in.reserve(368);
    unsigned char t[4], c=64, i=1, a;
    while(c < 368) {
      
      for(a=0; a<4; a++) 
	t[a] = in[a+c-4];
      
      if(c%64==0)
	schedule_core(t,i++);

      if(c%64==16||c%64==48)
	for(a = 0; a < 4; a++) 
	  t[a] = sbox(t[a]);
      
      if(c%64==32)
	for(a = 0; a < 4; a++) 
	  t[a] = sbox(sbox(t[a]));
      
      for(a = 0; a < 4; a++)
	in[c] = in[c++-64]^t[a];
    }
    return in;
  }

  std::vector<unsigned char> &expand_key_1024(std::vector<unsigned char> &in){
    in.reserve(624);
    unsigned char t[4], c=128, i=1, a;
    while(c < 624) {
      
      for(a=0; a<4; a++) 
	t[a] = in[a+c-4];
      
      if(c%128==0)
	schedule_core(t,i++);
      
      if(c%128==16||c%128==48||c%128==80||c%128==112)
	for(a = 0; a < 4; a++) 
	  t[a] = sbox(t[a]);

      if(c%128==32||c%128==96)
	for(a = 0; a < 4; a++) 
	  t[a] = sbox(sbox(t[a]));
      
      if(c%128==64)
	for(a = 0; a < 4; a++) 
	  t[a] = sbox(sbox(sbox(t[a])));
      
      for(a = 0; a < 4; a++)
	in[c] = in[c++-128]^t[a];
    }
    return in;
  }

}

using namespace RSA;

int main(){


  
  return 0;
}
