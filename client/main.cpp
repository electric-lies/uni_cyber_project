#include <boost/asio.hpp>
// #include <iostream>
// #include <iostream>
// #include <fstream>
#include <iostream>
#include <fstream>
#include <string>

using namespace std;

#include "RSAWrapper.h"

RSAPublicWrapper::RSAPublicWrapper(const char *key, unsigned int length)
{
    CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte *>(key), length, true);
    _publicKey.Load(ss);
}

RSAPublicWrapper::RSAPublicWrapper(const std::string &key)
{
    CryptoPP::StringSource ss(key, true);
    _publicKey.Load(ss);
}

RSAPublicWrapper::~RSAPublicWrapper()
{
}

std::string RSAPublicWrapper::getPublicKey() const
{
    std::string key;
    CryptoPP::StringSink ss(key);
    _publicKey.Save(ss);
    return key;
}

char *RSAPublicWrapper::getPublicKey(char *keyout, unsigned int length) const
{
    CryptoPP::ArraySink as(reinterpret_cast<CryptoPP::byte *>(keyout), length);
    _publicKey.Save(as);
    return keyout;
}

std::string RSAPublicWrapper::encrypt(const std::string &plain)
{
    std::string cipher;
    CryptoPP::RSAES_OAEP_SHA_Encryptor e(_publicKey);
    CryptoPP::StringSource ss(plain, true, new CryptoPP::PK_EncryptorFilter(_rng, e, new CryptoPP::StringSink(cipher)));
    return cipher;
}

std::string RSAPublicWrapper::encrypt(const char *plain, unsigned int length)
{
    std::string cipher;
    CryptoPP::RSAES_OAEP_SHA_Encryptor e(_publicKey);
    CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte *>(plain), length, true, new CryptoPP::PK_EncryptorFilter(_rng, e, new CryptoPP::StringSink(cipher)));
    return cipher;
}

RSAPrivateWrapper::RSAPrivateWrapper()
{
    _privateKey.Initialize(_rng, BITS);
}

RSAPrivateWrapper::RSAPrivateWrapper(const char *key, unsigned int length)
{
    CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte *>(key), length, true);
    _privateKey.Load(ss);
}

RSAPrivateWrapper::RSAPrivateWrapper(const std::string &key)
{
    CryptoPP::StringSource ss(key, true);
    _privateKey.Load(ss);
}

RSAPrivateWrapper::~RSAPrivateWrapper()
{
}

std::string RSAPrivateWrapper::getPrivateKey() const
{
    std::string key;
    CryptoPP::StringSink ss(key);
    _privateKey.Save(ss);
    return key;
}

char *RSAPrivateWrapper::getPrivateKey(char *keyout, unsigned int length) const
{
    CryptoPP::ArraySink as(reinterpret_cast<CryptoPP::byte *>(keyout), length);
    _privateKey.Save(as);
    return keyout;
}

std::string RSAPrivateWrapper::getPublicKey() const
{
    CryptoPP::RSAFunction publicKey(_privateKey);
    std::string key;
    CryptoPP::StringSink ss(key);
    publicKey.Save(ss);
    return key;
}

char *RSAPrivateWrapper::getPublicKey(char *keyout, unsigned int length) const
{
    CryptoPP::RSAFunction publicKey(_privateKey);
    CryptoPP::ArraySink as(reinterpret_cast<CryptoPP::byte *>(keyout), length);
    publicKey.Save(as);
    return keyout;
}

std::string RSAPrivateWrapper::decrypt(const std::string &cipher)
{
    std::string decrypted;
    CryptoPP::RSAES_OAEP_SHA_Decryptor d(_privateKey);
    CryptoPP::StringSource ss_cipher(cipher, true, new CryptoPP::PK_DecryptorFilter(_rng, d, new CryptoPP::StringSink(decrypted)));
    return decrypted;
}

std::string RSAPrivateWrapper::decrypt(const char *cipher, unsigned int length)
{
    std::string decrypted;
    CryptoPP::RSAES_OAEP_SHA_Decryptor d(_privateKey);
    CryptoPP::StringSource ss_cipher(reinterpret_cast<const CryptoPP::byte *>(cipher), length, true, new CryptoPP::PK_DecryptorFilter(_rng, d, new CryptoPP::StringSink(decrypted)));
    return decrypted;
}
// -------------------------------------------------------------

void hexify(const unsigned char *buffer, unsigned int length)
{
    std::ios::fmtflags f(std::cout.flags());
    std::cout << std::hex;
    for (size_t i = 0; i < length; i++)
        std::cout << (0xFF & buffer[i]) << (((i + 1) % 16 == 0) ? "\n" : " ");
    std::cout << std::endl;
    std::cout.flags(f);
}

using boost::asio::ip::tcp;

int main()
{
    ifstream config_file("transfer.info");

    string address_port;
    string user_name;
    string file_name;

    if (config_file.is_open())
    {
        getline(config_file, address_port);
        getline(config_file, user_name);
        getline(config_file, file_name);

        cout << "got " << address_port << ", " << user_name << ", " << file_name << '\n';

        config_file.close();
    }

    else
    {
        cout << "Unable to open file";
        return 1;
    }
    string address;
    string port;

    address = address_port.substr(0, address_port.find(":"));
    port = address_port.substr(address_port.find(":"), address_port.length());

    boost::asio::io_context io_context;
    tcp::socket s(io_context);
    tcp::resolver resolver(io_context);
    printf("here");
    boost::asio::connect(s, resolver.resolve(address, port));

    char header_client_id[16] = "123456789123456";
    int header_version = 3;
    int header_code = 1025;
    int header_payload_size = 255;

    // char content_name[header_payload_size] = user_name.substr(0, header_payload_size);

    int max_length = 1042;
    char request[max_length];

    // Start copying into the request buffer
    int offset = 0;

    // Copy the client ID
    memcpy(request + offset, header_client_id, sizeof(header_client_id));
    offset += sizeof(header_client_id);

    // Copy the version (considering endianess)
    memcpy(request + offset, &header_version, sizeof(header_version));
    offset += sizeof(header_version);

    // Copy the code
    memcpy(request + offset, &header_code, sizeof(header_code));
    offset += sizeof(header_code);

    // Copy the payload size
    memcpy(request + offset, &header_payload_size, sizeof(header_payload_size));
    offset += sizeof(header_payload_size);

    // Copy the content name (user_name's content)
    // memcpy(request + offset, content_name, sizeof(content_name));
    // Offset update not strictly necessary at this point unless more data follows

    boost::asio::write(s, boost::asio::buffer(request, offset));

    // std::cout << std::endl
    //           << std::endl
    //           << "----- RSA EXAMPLE -----" << std::endl
    //           << std::endl;

    // // plain text (could be binary data as well)
    // unsigned char plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    // std::cout << "plain:" << std::endl;
    // hexify(plain, sizeof(plain)); // print binary data nicely

    // // 1. Create an RSA decryptor. this is done here to generate a new private/public key pair
    // RSAPrivateWrapper rsapriv;

    // // 2. get the public key
    // std::string pubkey = rsapriv.getPublicKey(); // you can get it as std::string ...

    // char pubkeybuff[RSAPublicWrapper::KEYSIZE];
    // rsapriv.getPublicKey(pubkeybuff, RSAPublicWrapper::KEYSIZE); // ...or as a char* buffer

    // // 3. create an RSA encryptor
    // RSAPublicWrapper rsapub(pubkey);
    // std::string cipher = rsapub.encrypt((const char *)plain, sizeof(plain)); // you can encrypt a const char* or an std::string
    // std::cout << "cipher:" << std::endl;
    // hexify((unsigned char *)cipher.c_str(), cipher.length()); // print binary data nicely

    // // 4. get the private key and encode it as base64 (base64 in not necessary for an RSA decryptor.)

    // // 5. create another RSA decryptor using an existing private key (decode the base64 key to an std::string first)
    // RSAPrivateWrapper rsapriv_other(rsapriv.getPrivateKey());

    // std::string decrypted = rsapriv_other.decrypt(cipher); // 6. you can decrypt an std::string or a const char* buffer
    // std::cout << "decrypted:" << std::endl;
    // hexify((unsigned char *)decrypted.c_str(), decrypted.length()); // print binary data nicely

    return 0;
}

// using boost::asio::ip::tcp;

// int main()
// {
//     fstream my_file;
//     my_file.open ("transfer.info");
//     if (myfile.is_open()) { /* ok, proceed with output */ }

//     char address[] = "127.0.0.1";
//     char port[] = "1234";
//     boost::asio::io_context io_context;
//     tcp::socket s(io_context);
//     tcp::resolver resolver(io_context);
//     boost::asio::connect(s, resolver.resolve(address, port));
//     int max_length = 1042;
//     char request[max_length];
//     std::cout << "Enter message: ";
//     std::cin.getline(request, max_length);
//     boost::asio::write(s, boost::asio::buffer(request, max_length));
//     return 0;
// }