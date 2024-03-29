#include "Base64Wrapper.h"
#include <cryptopp/config_ns.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>

std::string Base64Wrapper::encode(const std::string &str)
{
	std::string encoded;
	CryptoPP::StringSource ss(str, true,
							  new CryptoPP::Base64Encoder(
								  new CryptoPP::StringSink(encoded)) // Base64Encoder
	);																 // StringSource

	return encoded;
}

std::string Base64Wrapper::decode(const std::string &str)
{
	std::string decoded;
	CryptoPP::StringSource ss(str, true,
							  new CryptoPP::Base64Decoder(
								  new CryptoPP::StringSink(decoded)) // Base64Decoder
	);																 // StringSource

	return decoded;
}
