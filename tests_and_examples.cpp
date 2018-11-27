#include "RSAES.hpp"
bool EncryptionManagerTest(bool print){
  std::string word_bank[100] = {
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
				"jagged",
				"tangy",
				"amuck",
				"joke",
				"lacking",
				"wry",
				"astonish",
				"weary",
				"key",
				"ready",
				"kick",
				"fry",
				"offend",
				"late",
				"locket",
				"quaint",
				"tail",
				"bomb",
				"slim",
				"medical",
				"scatter",
				"painful",
				"van",
				"mighty",
				"arm",
				"amusemen",
				"wretched",
				"sparkle",
				"petite",
				"second",
				"stuff",
				"judiciou",
				"love",
				"unnatura",
				"screw",
				"miniatur",
				"groan",
				"abhorren",
				"step",
				"pink",
				"tick",
				"clever",
				"therapeu",
				"fuzzy",
				"language",
				"toothsom",
				"rabbits",
				"money",
				"early",
				"futurist",
				"material"
  };
  std::uniform_int_distribution<unsigned short> dist_100(0, 99);
  try{
    std::cout << "Start encryption manager 1 and grab the RSA public key:" << std::endl;
    RSAES::EncryptionManager Bob(512);
    std::string msg = Bob.getPublicKey();
    std::cout << msg << std::endl << std::endl;

    std::cout << "Start encryption manager 2, generate a random AES key, and send it back encrypted over RSA:" << std::endl;
    RSAES::EncryptionManager Allice(msg, 128);
    msg = Allice.getKeyResponse();
    std::cout << msg << std::endl << std::endl;

    std::cout << "Register the AES key with manager 1. Now we can send a message:" << std::endl;
    Bob.registerPass(msg);
    std::string msg_s = word_bank[dist_100(RSAES::UTIL::mt)];
    int words = dist_100(RSAES::UTIL::mt);
    for(int i=0; i<words; ++i)
      (msg_s+=' ')+=word_bank[dist_100(RSAES::UTIL::mt)];
    msg = Bob.encrypt(msg_s);
    std::cout << msg << std::endl << std::endl;

    std::cout << "Now we can decrypt it using manager 2:" << std::endl;
    msg = Allice.decrypt(msg);
    std::cout << msg << std::endl << std::endl;
    if(msg!=msg_s)
      throw std::runtime_error("Messages aren't same");
  
    std::cout << "Now let's go the other way. Encrypt with manager 2:" << std::endl;
    msg_s = word_bank[dist_100(RSAES::UTIL::mt)];
    words = dist_100(RSAES::UTIL::mt);
    for(int i=0; i<words; ++i)
      (msg_s+=' ')+=word_bank[dist_100(RSAES::UTIL::mt)];
    msg = Allice.encrypt(msg_s);
    std::cout << msg << std::endl << std::endl;

    std::cout << "And decrypt with manager 1:" << std::endl;
    msg = Bob.decrypt(msg);
    std::cout << msg << std::endl << std::endl;
    if(msg!=msg_s)
      throw std::runtime_error("Messages aren't same");
  } catch (const std::runtime_error& error){
    return false;
  }
  return true;
}

int main(){

  unsigned int f=0;
  for(unsigned int done=0, s=0; done<10; ++done){
    if(EncryptionManagerTest(true))
      ++s;
    else
      ++f;
    std::cout << "-----------------------" << std::endl;
    std::cout << "SUCESSFULL TESTS: " << s << std::endl;
    std::cout << "FAILED TESTS: " << f << std::endl;
    std::cout << "-----------------------" << std::endl;
  }
  
  return 0;
}
