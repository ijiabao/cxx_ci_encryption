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



// 示例代码
namespace {




// 示例HexDecoder, String输出
inline void HexDecodeString(const string& src, string& out){
	StringSource(src, true, new HexDecoder(new StringSink(out)));
}

// 示例HexDecoder, bin输出
inline SecByteBlock HexDecodeString(const char* src, SecByteBlock& out){
	StringSource ss(src, true, new HexDecoder);	// 声明一个转换器
	out.resize((size_t) ss.MaxRetrievable());	// 计算输出长度
	ss.Get(out, out.size());					// 获取输出
}

// 示例 Put方法
void HexEncodeString(void* bin, size_t length, string& out){
	HexEncoder(new StringSink(out)).Put((byte*)bin, length);
}


// 通用StringSource输出为二制制(参见 HexDecodeString)
inline void SSGet(StringSource& ss, SecByteBlock& out){
	out.resize((size_t)ss.MaxRetrievable());
	ss.Get(out, out.size());
}

// 方便写代码而用的
inline SecByteBlock SSGet(StringSource& ss){
	SecByteBlock out;  SSGet(ss, out); return out;
}


};


namespace{
// 原始加密Key
static const char* __encryption_key = "3b9bddd542ce5b50f425a83ab44e812b";
};


Encryption::Encryption() : _digest_size(64){
	SSGet(StringSource(__encryption_key, true, new HexDecoder), _key);
}


// 使用hdkf 生成加密 key 和 散列(HMAC) Key
int Encryption::DeriveKeys(SecByteBlock& encrypt_key, SecByteBlock& hmac_key){
	//string key;
	//StringSource(_key, true, new HexDecoder(new StringSink(key)));
	string info("encryption");
	HKDF<SHA512> hkdf;
	encrypt_key.resize(_key.size());	// 与原始Key长度一致 (16位)
	int ret1 = hkdf.DeriveKey(encrypt_key, encrypt_key.size(), (byte*)_key.data(), _key.size(), 0, 0, (byte*)info.data(), info.size());

	info.assign("authentication");
	hmac_key.resize(_digest_size);
	int ret2 = hkdf.DeriveKey(hmac_key, hmac_key.size(), (byte*)_key.data(), _key.size(), 0, 0, (byte*)info.data(), info.size());
	return (ret1 == encrypt_key.size() && ret2 == _digest_size);
}

string Encryption::Encrypt(const string& data){

	// 取得加密key与散列Key
	SecByteBlock encrypt_key, hmac_key;
	if (!DeriveKeys(encrypt_key, hmac_key)){
		return "";
	}

	// 加密, 生成随机IV
	SecByteBlock iv(AES::BLOCKSIZE);
	RandomPool().GenerateBlock(iv.data(), iv.size());

	// CBC AES-128 加密
	SecByteBlock cipher;
	CBC_Mode<AES>::Encryption aes(encrypt_key, encrypt_key.size(), iv);	
	//StringSource(data, true, new StreamTransformationFilter(aes, new StringSink(cipher)));
	SSGet(StringSource(data, true, new StreamTransformationFilter(aes)), cipher);

	// 合并 iv 与 cipher
	cipher = iv + cipher;

	// base64 转码
	string cipher_base64;
	StringSource(cipher, cipher.size(), true, new Base64Encoder(new StringSink(cipher_base64), false));

	// 生成 HMAC SHA512 摘要 (对base64进行摘要)
	SecByteBlock hash;
	HMAC<SHA512> mac(hmac_key, hmac_key.size());
	SSGet(StringSource(cipher_base64, true, new HashFilter(mac)), hash);

	// hash 转码 (hexEncode)
	string hash_hex_encode;
	StringSource(hash, hash.size(), true, new HexEncoder(new StringSink(hash_hex_encode)));

	// 合并hash, 密文
	return hash_hex_encode + cipher_base64;
}

string Encryption::Decrypt(const string& data){
	string result;
	// 分离出hash (hexencodieng), 原始密文 (base64encoding)
	if (data.size() < _digest_size * 2){
		return result;
	}

	// 取得Key用于解密和哈希
	SecByteBlock encrypt_key, hmac_key;
	if (!DeriveKeys(encrypt_key, hmac_key)){
		return result;
	}

	string str_hash(data, 0, _digest_size * 2);	// 从0起始,取N位. 或 (data.c_str(), size)
	string str_cipher(data, str_hash.size());	// 从size起始取子串

	// 生成Hash
	SecByteBlock hash;
	HMAC<SHA512> mac(hmac_key, hmac_key.size());
	SSGet(StringSource(str_cipher, true, new HashFilter(mac)), hash);

	string hash_hex_encode;	// HexEncode 字符串
	StringSource(hash, hash.size(), true, new HexEncoder(new StringSink(hash_hex_encode)));

	// 验证Hash
	if (strcmpi(hash_hex_encode.c_str(), str_hash.c_str()) != 0){
		return result;
	}

	// 对密文进行 base64 解码
	SecByteBlock cipher;
	SSGet(StringSource(str_cipher, true, new Base64Decoder), cipher);
	if (cipher.size() <= AES::BLOCKSIZE){
		return result;
	}

	// 分离出IV, 密文	 (iv在前面)
	SecByteBlock iv(cipher, AES::BLOCKSIZE);
	SecByteBlock pure_cipher(cipher.data() + iv.size(), cipher.size() - iv.size());

	// 解密
	CBC_Mode<AES>::Decryption aes(encrypt_key, encrypt_key.size(), iv);
	StringSource(pure_cipher, pure_cipher.size(), true, new StreamTransformationFilter(aes, new StringSink(result)));
	return result;
}
