#include <gmpxx.h>
#include <limits>
#include <iostream>
#include <stdexcept>
#include <random>
#include <string>
#include <vector>
#include <cassert>

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
	e = r.get_z_range(USHRT_MAX)+USHRT_MAX; // Slightly more secure but terrible performance. Doesn't really matter though
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
}

using namespace RSA;

int main(){
  srand(time(NULL));

  EncryptionManager Allice(10000);
  
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

  return 0;
}
