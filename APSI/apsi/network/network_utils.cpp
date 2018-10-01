#include "apsi/network/network_utils.h"
#include <sstream>

using namespace std;
using namespace seal;
using namespace apsi::network;

namespace apsi
{
    void get_string(string& str, const PublicKey& pub_key)
    {
        stringstream ss;
        pub_key.save(ss);
        str = ss.str();
    }

    void get_string(string& str, const RelinKeys& relin_keys)
    {
        stringstream ss;
        relin_keys.save(ss);
        str = ss.str();
    }

    void get_string(string& str, const Ciphertext& ciphertext)
    {
        stringstream ss;
        ciphertext.save(ss);
        str = ss.str();
    }

    void get_public_key(seal::PublicKey& pub_key, const std::string& str)
    {
        stringstream ss(str);
        pub_key.load(ss);
    }

    void get_relin_keys(seal::RelinKeys& relin_keys, const std::string& str)
    {
        stringstream ss(str);
        relin_keys.load(ss);
    }

    void get_ciphertext(seal::Ciphertext& ciphertext, const std::string& str)
    {
        stringstream ss(str);
        ciphertext.load(ss);
    }
}
