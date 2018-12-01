#include "RSAES.hpp"
#include <iostream>  //     showing results of tests
#include <stdexcept> //     throwing errors in tests

std::string word_bank[50] = {
			      "pleasant",
			      "foot",
			      "elfin",
			      "calendar",
			      "settle",
			      "size",
			      "trip",
			      "float",
			      "sand",
			      "good",
			      "stain",
			      "trite",
			      "colorful",
			      "street",
			      "dusty",
			      "range",
			      "blot",
			      "direction",
			      "cent",
			      "white",
			      "angry",
			      "sack",
			      "wave",
			      "weather",
			      "stitch",
			      "ritzy",
			      "scintill",
			      "deliver",
			      "synonymo",
			      "quicksan",
			      "cub",
			      "sofa",
			      "callous",
			      "disagree",
			      "dashing",
			      "daughter",
			      "jar",
			      "sniff",
			      "ear",
			      "powder",
			      "wait",
			      "shame",
			      "needy",
			      "dreary",
			      "x-ray",
			      "labored",
			      "can",
			      "incompet",
			      "pricey",
			      "jagged"
};
std::uniform_int_distribution<unsigned short> dist_50(0, 49);

std::string test_high_level(){
  try{
    std::cout << "Start encryption manager 1 and grab the RSA public key:" << std::endl;
    RSAES::EncryptionManager Bob(2048);
    std::string msg = Bob.getPublicKey();
    std::cout << msg << std::endl << std::endl;

    std::cout << "Start encryption manager 2, generate a random AES key, and send it back encrypted over RSA:" << std::endl;
    RSAES::EncryptionManager Allice(msg);
    msg = Allice.getKeyResponse();
    std::cout << msg << std::endl << std::endl;

    std::cout << "Register the AES key with manager 1. Now we can send a message:" << std::endl;
    Bob.registerPass(msg);
    std::string msg_s = word_bank[dist_50(RSAES::UTIL::mt)];
    int words = dist_50(RSAES::UTIL::mt);
    for(int i=0; i<words; ++i)
      (msg_s+=' ')+=word_bank[dist_50(RSAES::UTIL::mt)];
    msg = Bob.encrypt(msg_s);
    std::cout << msg << std::endl << std::endl;

    std::cout << "Now we can decrypt it using manager 2:" << std::endl;
    msg = Allice.decrypt(msg);
    std::cout << msg << std::endl << std::endl;
    if(msg!=msg_s)
      throw std::runtime_error("Messages aren't same");
  
    std::cout << "Now let's go the other way. Encrypt with manager 2:" << std::endl;
    msg_s = word_bank[dist_50(RSAES::UTIL::mt)];
    words = dist_50(RSAES::UTIL::mt);
    for(int i=0; i<words; ++i)
      (msg_s+=' ')+=word_bank[dist_50(RSAES::UTIL::mt)];
    msg = Allice.encrypt(msg_s);
    std::cout << msg << std::endl << std::endl;

    std::cout << "And decrypt with manager 1:" << std::endl;
    msg = Bob.decrypt(msg);
    std::cout << msg << std::endl << std::endl;
    if(msg!=msg_s)
      throw std::runtime_error("Messages aren't same");
  } catch (const std::runtime_error& error){
    return error.what();
  }
  return "";
}

std::string test_low_level_RSA(){
  try{
    std::cout << "Start an RSAmanager and grab the public key:" << std::endl;
    RSAES::RSA::RSAmanager Bob(1024);
    std::string keyStr = RSAES::RSA::packKey(Bob.public_key);
    std::cout << keyStr << std::endl << std::endl;

    std::cout << "Encrypt a message using the public key:" << std::endl;
    std::string msg_s = word_bank[dist_50(RSAES::UTIL::mt)];
    int words = dist_50(RSAES::UTIL::mt)/2;
    for(int i=0; i<words; ++i)
      (msg_s+=' ')+=word_bank[dist_50(RSAES::UTIL::mt)];
    std::pair<mpz_t,mpz_t> *recvKey = new std::pair<mpz_t,mpz_t>;
    mpz_init(recvKey->first);
    mpz_init(recvKey->second);
    RSAES::RSA::unpackKey(&recvKey, keyStr);
    std::string msg = RSAES::RSA::encrypt(msg_s, recvKey);
    mpz_clear(recvKey->first);
    mpz_clear(recvKey->second);
    delete recvKey;
    std::cout << msg << std::endl << std::endl;

    std::cout << "Decrypt the message using the private key:" << std::endl;
    msg = Bob.decrypt(msg);
    std::cout << msg << std::endl << std::endl;
    if(msg_s!=msg)
      throw std::runtime_error("Messages aren't same");
  } catch (const std::runtime_error& error){
    return error.what();
  }
  return "";
}

std::string test_low_level_AES(){
  try{
    std::cout << "Start an AESkey and encrypt a message at 128 bits key size" << std::endl;
    RSAES::AES::AESkey Bob(128);
    std::string msg_s = word_bank[dist_50(RSAES::UTIL::mt)];
    int words = dist_50(RSAES::UTIL::mt);
    for(int i=0; i<words; ++i)
      (msg_s+=' ')+=word_bank[dist_50(RSAES::UTIL::mt)];
    std::string msg = RSAES::AES::big_encrypt(msg_s, Bob);
    std::cout << msg << std::endl << std::endl;

    std::cout << "Decrypt the message using the key" << std::endl;
    msg = RSAES::AES::big_decrypt(msg, Bob);
    std::cout << msg << std::endl << std::endl;
    {
      std::cout << "For reference, the key in base64:" << std::endl;
      auto p = Bob.expanded_key.begin();
      std::vector<unsigned char> exp(p, p+Bob.base); // send the un-expanded key so that we need less data to send
      std::string AES_string(exp.begin(), exp.end());
      std::cout << RSAES::UTIL::base64_encode((const unsigned char*)AES_string.c_str(), AES_string.size()) << std::endl << std::endl;
    }
    if(msg_s!=msg)
      throw std::runtime_error("Messages aren't same - small");



    
    std::cout << "Start an AESkey and encrypt a message at 1 megabit key size" << std::endl;
    RSAES::AES::AESkey Allice(1048576);
    msg_s = word_bank[dist_50(RSAES::UTIL::mt)];
    words = dist_50(RSAES::UTIL::mt);
    for(int i=0; i<words; ++i)
      (msg_s+=' ')+=word_bank[dist_50(RSAES::UTIL::mt)];
    msg = RSAES::AES::big_encrypt(msg_s, Allice);
    std::cout << msg << std::endl << std::endl;

    std::cout << "Decrypt the message using the key" << std::endl;
    msg = RSAES::AES::big_decrypt(msg, Allice);
    std::cout << msg << std::endl << std::endl;
    if(msg_s!=msg)
      throw std::runtime_error("Messages aren't same - small");
  } catch (const std::runtime_error& error){
    return error.what();
  }
  return "";
}

bool test_gigabit(){
  try{
    std::cout << "Create and expand an AESkey of 1 gigabit key size" << std::endl;
    RSAES::AES::AESkey Allice(1073741824);
    std::cout << "Key created. Encrypt the message using the key" << std::endl;
    std::string msg_s = word_bank[dist_50(RSAES::UTIL::mt)];

    for(int i=0; i<50; ++i)
      (msg_s+=' ')+=word_bank[dist_50(RSAES::UTIL::mt)];
    std::string msg = RSAES::AES::big_encrypt(msg_s, Allice);
    std::cout << msg << std::endl << std::endl;

    std::cout << "Decrypt the message using the key" << std::endl;
    msg = RSAES::AES::big_decrypt(msg, Allice);
    std::cout << msg << std::endl << std::endl;
    if(msg_s!=msg)
      throw std::runtime_error("Messages aren't same - gigabit");
  } catch (const std::runtime_error& error){
    return false;
  }
  return true;
}


int main(){
  std::cout << "TESTING HIGH LEVEL INTERFACE" << std::endl;

  unsigned int f_high=0, s_high=0;
  for(unsigned int done=0; done<10; ++done){
    std::string result = test_high_level();
    if(result=="")
      ++s_high;
    else {
      ++f_high;
      std::cout << "TEST FAILED WITH MESSAGE: " << std::endl << result << std::endl;
    }
    std::cout << "-----------------------" << std::endl;
    std::cout << "HIGH LEVEL INTERFACE" << std::endl;
    std::cout << "SUCESSFULL TESTS: " << s_high << std::endl;
    std::cout << "FAILED TESTS: " << f_high << std::endl;
    std::cout << "-----------------------" << std::endl;
  }
  
  std::cout << "TESTING LOW LEVEL INTERFACE - RSA" << std::endl;

  unsigned int f_rsa=0, s_rsa=0;
  for(unsigned int done=0; done<10; ++done){
    std::string result = test_low_level_RSA();
    if(result=="")
      ++s_rsa;
    else {
      ++f_rsa;
      std::cout << "TEST FAILED WITH MESSAGE: " << std::endl << result << std::endl;
    }
    std::cout << "-----------------------" << std::endl;
    std::cout << "LOW LEVEL INTERFACE RSA" << std::endl;
    std::cout << "SUCESSFULL TESTS: " << s_rsa << std::endl;
    std::cout << "FAILED TESTS: " << f_rsa << std::endl;
    std::cout << "-----------------------" << std::endl;
  }
  
  std::cout << "TESTING LOW LEVEL INTERFACE - AES" << std::endl;

  unsigned int f_aes=0, s_aes=0;
  for(unsigned int done=0; done<10; ++done){
    std::string result = test_low_level_AES();
    if(result=="")
      ++s_aes;
    else {
      ++f_aes;
      std::cout << "TEST FAILED WITH MESSAGE: " << std::endl << result << std::endl;
    }
    std::cout << "-----------------------" << std::endl;
    std::cout << "LOW LEVEL INTERFACE AES" << std::endl;
    std::cout << "SUCESSFULL TESTS: " << s_aes << std::endl;
    std::cout << "FAILED TESTS: " << f_aes << std::endl;
    std::cout << "-----------------------" << std::endl;
  }
  
  std::cout << "TESTING LOW LEVEL INTERFACE - AES AT 1 GIGABIT KEY SIZE" << std::endl;
  bool s_gigabit = test_gigabit();
  if(!s_gigabit)
      std::cout << "TEST FAILED WITH MESSAGE: " << std::endl << "Messages aren't same - gigabit" << std::endl;
  std::cout << "-----------------------" << std::endl;
  std::cout << "GIGABIT AES LOW LEVEL  " << std::endl;
  std::cout << "TEST " << (s_gigabit?"PASSED":"FAILED") << std::endl;
  std::cout << "-----------------------" << std::endl;
    

  std::cout << std::endl << "TEST RESULTS:" << std::endl;
  std::cout << "-----------------------" << std::endl;
  std::cout << "HIGH LEVEL INTERFACE" << std::endl;
  std::cout << "SUCESSFULL TESTS: " << s_high << std::endl;
  std::cout << "FAILED TESTS: " << f_high << std::endl;
  std::cout << "-----------------------" << std::endl;
  std::cout << "LOW LEVEL INTERFACE RSA" << std::endl;
  std::cout << "SUCESSFULL TESTS: " << s_rsa << std::endl;
  std::cout << "FAILED TESTS: " << f_rsa << std::endl;
  std::cout << "-----------------------" << std::endl;
  std::cout << "LOW LEVEL INTERFACE AES" << std::endl;
  std::cout << "SUCESSFULL TESTS: " << s_aes << std::endl;
  std::cout << "FAILED TESTS: " << f_aes << std::endl;
  std::cout << "-----------------------" << std::endl;
  std::cout << "GIGABIT AES LOW LEVEL  " << std::endl;
  std::cout << "TEST " << (s_gigabit?"PASSED":"FAILED") << std::endl;
  std::cout << "-----------------------" << std::endl;

  if(!f_high && !f_rsa && !f_aes && s_gigabit)
    std::cout << "PASSED TESTS" << std::endl;
  else
    std::cout << "FAILED TESTS" << std::endl;
  
  return 0;
}
