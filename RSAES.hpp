#ifndef __RSAES__
#define __RSAES__
#include "impl.hpp"

namespace RSAES{
  class EncryptionManager{
  public:
    //Constructors
    EncryptionManager(unsigned int RSAbits); // we're sending out the public key
    EncryptionManager(std::string const& key); // we're recieving the public key and generating a pass for AES
                                               // key is the result of getPublicKey from an object initilized using the first constructor
    EncryptionManager(std::string const& key, size_t AESbits);// Same as above, but specify AES size
    EncryptionManager(); // create an empty object just for unpacking
    ~EncryptionManager();
    
    //Lifetime methods
    std::string getPublicKey(); // Called after EncryptionManager(unsigned int RSAbits)
    std::string getKeyResponse(); // Called after EncryptionManager(std::string const& key)
    void registerPass(std::string KeyResponse); // Called after getPublicKey(). KeyResponse is the result of getKeyResponse from another object 
    std::string encrypt(std::string const& input); // Encrypt using AES-N
    std::string decrypt(std::string const& input); // Decrypt from AES-N

    //Maintainence
    inline std::string pack(); // Packs up fully initilized classes as a string to be saved to disk
    void unpack(std::string KeyResponse); // Takes the result of pack() and creates an object to resume operation
    void destroy(); // Clears the object so that it can be unpacked() into
  
  private:
    gmp_randstate_t r; // The source of RSA randomness
    RSA::RSAmanager* rsaCore; // The generator of RSA keys. Used to send out a public key
    std::pair<mpz_t,mpz_t> *unpacked_key; // used in recieving a public key
    AES::AESkey* AES_key; // The AES-N hash used in decryption
    void __destroy();
  };
}

#include "EncryptionManager.hpp"
#endif // __RSAES__
