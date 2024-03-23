#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"

#include <iostream>
#include <iomanip>

void hexify(const unsigned char *buffer, unsigned int length)
{
    std::ios::fmtflags f(std::cout.flags());
    std::cout << std::hex;
    for (size_t i = 0; i < length; i++)
        std::cout << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]) << (((+1) % 16 == 0) ? "\n" : " ");
    std::cout << std::endl;
    std::cout.flags(f);
}

int aes_example()
{
    std::cout << std::endl
              << std::endl
              << "----- AES EXAMPLE -----" << std::endl
              << std::endl;

    std::string plaintext = "hello world!!!!!";
    std::cout
        << "Plain:" << std::endl
        << plaintext << std::endl;
    // unsigned char key[AESWrapper::DEFAULT_KEYLENGTH];

    CryptoPP::byte byteval[AESWrapper::DEFAULT_KEYLENGTH] = {0};

    // std::cout << byteval[0] << "," << byteval[1] << std::endl;
    AESWrapper aes(byteval, AESWrapper::DEFAULT_KEYLENGTH);

    // 2. encrypt a message (plain text)
    std::string ciphertext = aes.encrypt(plaintext.c_str(), plaintext.length());
    std::cout << "Cipher:" << std::endl;
    hexify(reinterpret_cast<const unsigned char *>(ciphertext.c_str()), ciphertext.length()); // print binary data nicely

    // 3. decrypt a message (cipher text)
    std::string decrypttext = aes.decrypt(ciphertext.c_str(), ciphertext.length());
    std::cout << "Decrypted:" << std::endl
              << decrypttext << std::endl;

    return 0;
}

int main()
{
    aes_example();
    return 0;
}