#pragma warning (disable:4996)
#include "encryption.h"

#include <hex.h>
#include <modes.h>
#include <randpool.h>
#include <hkdf.h>
#include <sha.h>
#include <base64.h>


#pragma comment (lib, "cryptlib.lib")

using namespace std;



// ʾ������
namespace {




// ʾ��HexDecoder, String���
inline void HexDecodeString(const string& src, string& out){
	StringSource(src, true, new HexDecoder(new StringSink(out)));
}

// ʾ��HexDecoder, bin���
inline SecByteBlock HexDecodeString(const char* src, SecByteBlock& out){
	StringSource ss(src, true, new HexDecoder);	// ����һ��ת����
	out.resize((size_t) ss.MaxRetrievable());	// �����������
	ss.Get(out, out.size());					// ��ȡ���
}

// ʾ�� Put����
void HexEncodeString(void* bin, size_t length, string& out){
	HexEncoder(new StringSink(out)).Put((byte*)bin, length);
}


// ͨ��StringSource���Ϊ������(�μ� HexDecodeString)
inline void SSGet(StringSource& ss, SecByteBlock& out){
	out.resize((size_t)ss.MaxRetrievable());
	ss.Get(out, out.size());
}

// ����д������õ�
inline SecByteBlock SSGet(StringSource& ss){
	SecByteBlock out;  SSGet(ss, out); return out;
}


};


namespace{
// ԭʼ����Key
static const char* __encryption_key = "3b9bddd542ce5b50f425a83ab44e812b";
};


Encryption::Encryption() : _digest_size(64){
	SSGet(StringSource(__encryption_key, true, new HexDecoder), _key);
}


// ʹ��hdkf ���ɼ��� key �� ɢ��(HMAC) Key
int Encryption::DeriveKeys(SecByteBlock& encrypt_key, SecByteBlock& hmac_key){
	//string key;
	//StringSource(_key, true, new HexDecoder(new StringSink(key)));
	string info("encryption");
	HKDF<SHA512> hkdf;
	encrypt_key.resize(_key.size());	// ��ԭʼKey����һ�� (16λ)
	int ret1 = hkdf.DeriveKey(encrypt_key, encrypt_key.size(), (byte*)_key.data(), _key.size(), 0, 0, (byte*)info.data(), info.size());

	info.assign("authentication");
	hmac_key.resize(_digest_size);
	int ret2 = hkdf.DeriveKey(hmac_key, hmac_key.size(), (byte*)_key.data(), _key.size(), 0, 0, (byte*)info.data(), info.size());
	return (ret1 == encrypt_key.size() && ret2 == _digest_size);
}

string Encryption::Encrypt(const string& data){

	// ȡ�ü���key��ɢ��Key
	SecByteBlock encrypt_key, hmac_key;
	if (!DeriveKeys(encrypt_key, hmac_key)){
		return "";
	}

	// ����, �������IV
	SecByteBlock iv(AES::BLOCKSIZE);
	RandomPool().GenerateBlock(iv.data(), iv.size());

	// CBC AES-128 ����
	SecByteBlock cipher;
	CBC_Mode<AES>::Encryption aes(encrypt_key, encrypt_key.size(), iv);	
	//StringSource(data, true, new StreamTransformationFilter(aes, new StringSink(cipher)));
	SSGet(StringSource(data, true, new StreamTransformationFilter(aes)), cipher);

	// �ϲ� iv �� cipher
	cipher = iv + cipher;

	// base64 ת��
	string cipher_base64;
	StringSource(cipher, cipher.size(), true, new Base64Encoder(new StringSink(cipher_base64), false));

	// ���� HMAC SHA512 ժҪ (��base64����ժҪ)
	SecByteBlock hash;
	HMAC<SHA512> mac(hmac_key, hmac_key.size());
	SSGet(StringSource(cipher_base64, true, new HashFilter(mac)), hash);

	// hash ת�� (hexEncode)
	string hash_hex_encode;
	StringSource(hash, hash.size(), true, new HexEncoder(new StringSink(hash_hex_encode)));

	// �ϲ�hash, ����
	return hash_hex_encode + cipher_base64;
}

string Encryption::Decrypt(const string& data){
	string result;
	// �����hash (hexencodieng), ԭʼ���� (base64encoding)
	if (data.size() < _digest_size * 2){
		return result;
	}

	// ȡ��Key���ڽ��ܺ͹�ϣ
	SecByteBlock encrypt_key, hmac_key;
	if (!DeriveKeys(encrypt_key, hmac_key)){
		return result;
	}

	string str_hash(data, 0, _digest_size * 2);	// ��0��ʼ,ȡNλ. �� (data.c_str(), size)
	string str_cipher(data, str_hash.size());	// ��size��ʼȡ�Ӵ�

	// ����Hash
	SecByteBlock hash;
	HMAC<SHA512> mac(hmac_key, hmac_key.size());
	SSGet(StringSource(str_cipher, true, new HashFilter(mac)), hash);

	string hash_hex_encode;	// HexEncode �ַ���
	StringSource(hash, hash.size(), true, new HexEncoder(new StringSink(hash_hex_encode)));

	// ��֤Hash
	if (strcmpi(hash_hex_encode.c_str(), str_hash.c_str()) != 0){
		return result;
	}

	// �����Ľ��� base64 ����
	SecByteBlock cipher;
	SSGet(StringSource(str_cipher, true, new Base64Decoder), cipher);
	if (cipher.size() <= AES::BLOCKSIZE){
		return result;
	}

	// �����IV, ����	 (iv��ǰ��)
	SecByteBlock iv(cipher, AES::BLOCKSIZE);
	SecByteBlock pure_cipher(cipher.data() + iv.size(), cipher.size() - iv.size());

	// ����
	CBC_Mode<AES>::Decryption aes(encrypt_key, encrypt_key.size(), iv);
	StringSource(pure_cipher, pure_cipher.size(), true, new StreamTransformationFilter(aes, new StringSink(result)));
	return result;
}
