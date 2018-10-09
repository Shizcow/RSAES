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

  void testRSA(unsigned int bits){

    EncryptionManager Allice(bits);
    
    std::cout << "First, send the public key:" << std::endl;
    std::string msg = Allice.getPublicKey();
    std::cout << msg << std::endl << std::endl;
    
    EncryptionManager Bob(msg);
    
    msg = Bob.getKeyResponse();
    
    std::cout << "Then, send an encrypted response containing a SHA password:" << std::endl;
    std::cout << msg << std::endl << std::endl;
    
    Allice.registerPass(msg);
    assert(Allice.SHA_string == Bob.SHA_string);
    std::cout << "Register password on side one. Recieved password is below:" << std::endl;
    std::cout << Allice.SHA_string << std::endl << std::endl;
  }

  void testRSA(){
    testRSA(256);
  }

  //starting AES stuff
  
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
  
  std::array<unsigned char, 176> expand_key(std::array<unsigned char, 16> in) { // 128 bit key
    std::array<unsigned char, 176> out;
    std::copy_n(in.begin(), 16, out.begin());
    unsigned char t[4], c = 16, i = 1, a;

    while(c<176){
      
      for(a=0; a<4; a++) 
	t[a] = out[a+c-4];
      
      if(c%16==0)
	schedule_core(t,i++);
      
      for(a = 0; a<4; a++)
	out[c] = out[c++-16]^t[a];
    }
    return out;
  }

  std::array<unsigned char, 240> expand_key(std::array<unsigned char, 32> in){ // 256 bit key
    std::array<unsigned char, 240> out;
    std::copy_n(in.begin(), 32, out.begin());
    unsigned char t[4], c=32, i=1, a;
    while(c < 240) {
      
      for(a=0; a<4; a++) 
	t[a] = out[a+c-4];
      
      if(c%32==0)
	schedule_core(t,i++);
      
      if(c%32==16)
	for(a = 0; a < 4; a++) 
	  t[a] = sbox(t[a]);
      
      for(a = 0; a < 4; a++)
	out[c] = out[c++-32]^t[a];
    }
    return out;
  }

  std::array<unsigned char, 368> expand_key(std::array<unsigned char, 64> in){ // 512 bit key
    std::array<unsigned char, 368> out;
    std::copy_n(in.begin(), 64, out.begin());
    unsigned char t[4], i=1, a;
    unsigned int c=64;
    while(c < 368) {
      
      for(a=0; a<4; a++) 
	t[a] = out[a+c-4];
      
      if(c%64==0)
	schedule_core(t,i++);

      if(c%64==16||c%64==48)
	for(a = 0; a < 4; a++) 
	  t[a] = sbox(t[a]);
      
      if(c%64==32)
	for(a = 0; a < 4; a++) 
	  t[a] = sbox(sbox(t[a]));
      
      for(a = 0; a < 4; a++)
	out[c] = out[c++-64]^t[a];

    }
    return out;
  }

  std::array<unsigned char, 624> expand_key(std::array<unsigned char, 128> in){ // 1024 bit key
    std::array<unsigned char, 624> out;
    std::copy_n(in.begin(), 128, out.begin());
    unsigned char t[4], i=1, a;
    unsigned int c=128;
    while(c < 624) {
      
      for(a=0; a<4; a++) 
	t[a] = out[a+c-4];
      
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
	out[c] = out[c++-128]^t[a];
    }
    return out;
  }

  
  template<size_t size>
  struct key{
    std::array<unsigned char, size*4+112> expanded_key;
    unsigned int idx;
    key(std::array<unsigned char, size> in) : expanded_key(expand_key(in)), idx(0) {}
    std::array<unsigned char, 16> getRoundKey(){
      std::array<unsigned char, 16> ret;
      std::copy_n(expanded_key.begin()+idx*16, 16, ret.begin());
      return ret;
    }
    inline void advanceRound(){++idx;}
  };

  unsigned char (&addRoundKey(unsigned char (&in)[4][4], std::array<unsigned char, 16> &key))[4][4]{
    for(char i=0; i<4; ++i)
      for(char j=0; j<4; ++j)
	in[i][j]^=key[4*i+j];
    return in;
  }

  unsigned char (&shiftrRows_encrypt(unsigned char (&rows)[4][4]))[4][4]{ // reference for slight speed boost
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
  unsigned char (&shiftRows_decrypt(unsigned char (&rows)[4][4]))[4][4]{ // reference for slight speed boost
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
  
}

using namespace RSA;
using namespace std;

int main(){

  cout << "unsigned char stable_inv[256] = {";
  
    for(int i=0; i<16; ++i){
      for(int j=0; j<16; ++j)
	cout << (int)sbox_inv(i*16+j) << ", ";
      putchar('\n');
    }

  
  return 0;
}
