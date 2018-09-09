#pragma once

#include <iostream>
#include <secblock.h>

using namespace CryptoPP;
using namespace std;


// ������AES-128-CBC + HMAC SHA512
class Encryption{
protected:
	SecByteBlock _key;			// �����Key bin
	size_t _digest_size;	// [sha512=64λ], 384=>48, 256=>32, 224=>28
public:
	Encryption();
	~Encryption(){};

	int DeriveKeys(SecByteBlock& encrypt_key, SecByteBlock& hmac_key);

	string Encrypt(const string& data);
	string Decrypt(const string& data);

};





