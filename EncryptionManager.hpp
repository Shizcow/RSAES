#ifndef __RSAES_ENC__
#define __RSAES_ENC__

namespace RSAES{
  class EncryptionManager;
  EncryptionManager::EncryptionManager() : rsaCore(nullptr), unpacked_key(nullptr), AES_key(nullptr){
    gmp_randinit_default(r);
    unsigned long seed;
    if(RAND_bytes((unsigned char*)&seed, sizeof(unsigned long))!=1)
      throw std::runtime_error("Openssl rand error");
    gmp_randseed_ui(r, seed);
  }; // create an empty object just for unpacking
  EncryptionManager::EncryptionManager(unsigned int RSAbits): rsaCore(nullptr), unpacked_key(nullptr), AES_key(nullptr){ // we're sending out the public key
    gmp_randinit_default(r);
    unsigned long seed;
    if(RAND_bytes((unsigned char*)&seed, sizeof(unsigned long))!=1)
      throw std::runtime_error("Openssl rand error");
    gmp_randseed_ui(r, seed);
    rsaCore = new RSA::RSAmanager(RSAbits);
  }
  EncryptionManager::EncryptionManager(std::string const& key): rsaCore(nullptr), unpacked_key(nullptr), AES_key(nullptr){ // we're recieving the public key and generating a pass for AES
    gmp_randinit_default(r);
    unsigned long seed;
    if(RAND_bytes((unsigned char*)&seed, sizeof(unsigned long))!=1)
      throw std::runtime_error("Openssl rand error");
    gmp_randseed_ui(r, seed);
    RSA::unpackKey(&unpacked_key, key);      
    size_t AESbits = static_cast<size_t>(pow(2, (size_t)log2(mpz_sizeinbase(unpacked_key->first, 2)-1) + 1)); // round up to next power of two, unless already a power of 2. This gives the largest key size that we can send over with a given RSA key.
    //generate random pass
    AES_key = new AES::AESkey(AESbits);
  }
  EncryptionManager::EncryptionManager(std::string const& key, size_t AESbits): rsaCore(nullptr), unpacked_key(nullptr), AES_key(nullptr){ // specify AES size
    gmp_randinit_default(r);
    unsigned long seed;
    if(RAND_bytes((unsigned char*)&seed, sizeof(unsigned long))!=1)
      throw std::runtime_error("Openssl rand error");
    gmp_randseed_ui(r, seed);
    RSA::unpackKey(&unpacked_key, key);
    AES_key = new AES::AESkey(AESbits);
  }

  void EncryptionManager::__destroy(){
    if(rsaCore!=nullptr){
      delete rsaCore;
      rsaCore=nullptr;
    }
    if(unpacked_key!=nullptr){
      mpz_urandomb(unpacked_key->first, r, mpz_sizeinbase(unpacked_key->first, 32)); // scramble ram just in case
      mpz_urandomb(unpacked_key->second, r, mpz_sizeinbase(unpacked_key->second, 32));
      mpz_clear(unpacked_key->first);
      mpz_clear(unpacked_key->second);
      delete unpacked_key;
      unpacked_key=nullptr;
    }
    if(AES_key!=nullptr){
      delete AES_key;
      AES_key=nullptr;
    }
    gmp_randclear(r);
  }

  EncryptionManager::~EncryptionManager(){
    __destroy();
  }

  void EncryptionManager::destroy(){
    __destroy();
    gmp_randinit_default(r);
    unsigned long seed;
    if(RAND_bytes((unsigned char*)&seed, sizeof(unsigned long))!=1)
      throw std::runtime_error("Openssl rand error");
    gmp_randseed_ui(r, seed);
  }

  std::string EncryptionManager::getPublicKey(){
    if(rsaCore==nullptr)
      throw std::runtime_error("This object doesn't have a core attached");
    return RSA::packKey(rsaCore->public_key);
  }

  std::string EncryptionManager::getKeyResponse(){
    if(AES_key==nullptr)
      throw std::runtime_error("This object hasn't been initilized correctly");
      
    char *p = (char*) AES_key->expanded_key.data();
    std::string AES_string(p, p+AES_key->base); // send the un-expanded key so that we need less data to send
      
    std::string ret = RSA::encrypt(AES_string, unpacked_key);
    mpz_urandomb(unpacked_key->first, r, mpz_sizeinbase(unpacked_key->first, 32)); // scramble ram just in case
    mpz_urandomb(unpacked_key->second, r, mpz_sizeinbase(unpacked_key->second, 32));
    mpz_clear(unpacked_key->first);
    mpz_clear(unpacked_key->second);
    delete unpacked_key; // might as well get rid of this
    unpacked_key = nullptr;
    return ret;
  }

  void EncryptionManager::registerPass(std::string KeyResponse){
    KeyResponse = rsaCore->decrypt(KeyResponse);
    std::vector<unsigned char> exp(KeyResponse.size());
    memcpy(exp.data(), KeyResponse.data(), KeyResponse.size()); // This gets ndk to shut up

    AES_key = new AES::AESkey(exp);
    delete rsaCore; // dont need this anymore either
    rsaCore = nullptr;
  }

  std::string EncryptionManager::encrypt(std::string const& input){
    if(AES_key==nullptr)
      throw std::runtime_error("Object not properly initialized");
    return AES::big_encrypt(input, *AES_key);
  }

  std::string EncryptionManager::decrypt(std::string const& input){
    if(AES_key==nullptr)
      throw std::runtime_error("Object not properly initialized");
    return AES::big_decrypt(input, *AES_key);
  }

  inline std::string EncryptionManager::pack(){ // Packs up the entire class as a string to be saved on disk or something similar. Only for fully initilized classes
    size_t pack_s;
    unsigned char* ret = AES_key->pack(&pack_s);
    std::string ret_str;
    ret_str.resize(pack_s);
    memcpy((char*)ret_str.data(), ret, pack_s);
    free(ret);
    return ret_str; // we can squeeze in these optimizations here because we don't need to encrypt it with RSA
  }

  void EncryptionManager::unpack(std::string KeyResponse){
    size_t keyRes_s;
    unsigned char *KeyResponse_p = UTIL::base64_decode((const unsigned char*)KeyResponse.data(), KeyResponse.size(), &keyRes_s);
    std::vector<unsigned char> exp(keyRes_s); // TODO: optimize out the vector
    memcpy(exp.data(), KeyResponse_p, keyRes_s); // This gets ndk to shut up
    free(KeyResponse_p);
    AES_key = new AES::AESkey(exp);
  }
}

#endif //__RSAES_ENC__
