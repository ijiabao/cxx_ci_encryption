# cxx_ci_encryption
C++(CrytpoPP) 与 CI(CodeIgniter PHP) 实现相同加解密算法(Crypt AES-128-CBC/HMAC SHA512)

## 前言
* 如果服务器端数据需要与其它应用程序交互，很可能需要进行加密与解密
* CI自带一个Encryption库，默认使用使用AES-128-CBC/HMAC SHA512算法，如果使用VC客户端请求服务器数据时数据是加密的，需要实现相同算法来进行解密。
* CI的Encryption库也是可移植的，可应用到其它PHP框架


### CI libraries\Encryption.php 算法简述
加密： 
`$this->encryption->encrypt($plain_text)`

* 通过 HKDF 和 SHA-512 摘要算法，从你配置的 encryption_key 参数中获取两个密钥：加密密钥 和 HMAC 密钥。
* 生成一个随机的初始向量（IV）。
* 使用上面的加密密钥和 IV ，通过 AES-128 算法的 CBC 模式（或其他你配置的算法和模式）对数据进行加密。
* 将 IV 附加到密文后。
* 对结果进行 Base64 编码，这样就可以安全的保存和传输它，而不用担心字符集问题。
* 使用 HMAC 密钥生成一个 SHA-512 HMAC 认证消息，附加到 Base64 字符串后，以保证数据的完整性。

解密：
`$this->encryption->decrypt($ciphertext)`

* 通过 HKDF 和 SHA-512 摘要算法，从你配置的 encryption_key 参数中获取两个密钥：加密密钥 和 HMAC 密钥。 由于 encryption_key 不变，所以生成的结果和上面 encrypt() 方法生成的结果是一样的，否则你没办法解密。
* 检查字符串的长度是否足够长，并从字符串中分离出 HMAC ，然后验证是否一致（这可以防止时序攻击）， 如果验证失败，返回 FALSE 。
* 进行 Base64 解码。
* 从密文中分离出 IV ，并使用 IV 和 加密密钥对数据进行解密。

### 源码分析
```
// 原始key在配置文件 $config['encryption_key'] = hex2bin('3b9bddd542ce5b50f425a83ab44e812b');

	// 加密部分
	public function encrypt($data, array $params = NULL)
	{
		//...参数验证
		
		// hkdf函数，根据原始key, 生成加密key与散列key, 需要VC实现
		isset($params['key']) OR $params['key'] = $this->hkdf($this->_key, 'sha512', NULL, self::strlen($this->_key), 'encryption');
		// 根据配置，调用相关库 (crypt或openssl)加密核心算法, 本文实现crypt
		if (($data = $this->{'_'.$this->_driver.'_encrypt'}($data, $params)) === FALSE)
		{
			return FALSE;
		}
		// base64转码
		$params['base64'] && $data = base64_encode($data);
		// 生成hmac sha512 hash
		if (isset($params['hmac_digest']))
		{
			isset($params['hmac_key']) OR $params['hmac_key'] = $this->hkdf($this->_key, 'sha512', NULL, NULL, 'authentication');
			return hash_hmac($params['hmac_digest'], $data, $params['hmac_key'], ! $params['base64']).$data;
		}

		return $data;
	}
	
	// Crypt加密核心算法
	protected function _mcrypt_encrypt($data, $params)
	{
		// 'handle' = mcrypt_module_open($this->_cipher, '', $this->_mode, '')
		if ( ! is_resource($params['handle']))
		{
			return FALSE;
		}

		// 生成IV
		$iv = (($iv_size = mcrypt_enc_get_iv_size($params['handle'])) > 1)
			? $this->create_key($iv_size)
			: NULL;
		// 初始化算法
		if (mcrypt_generic_init($params['handle'], $params['key'], $iv) < 0)
		{
			if ($params['handle'] !== $this->_handle)
			{
				mcrypt_module_close($params['handle']);
			}

			return FALSE;
		}

		// CBC/EBC 原始数据长度fix
		if (in_array(strtolower(mcrypt_enc_get_modes_name($params['handle'])), array('cbc', 'ecb'), TRUE))
		{
			$block_size = mcrypt_enc_get_block_size($params['handle']);
			$pad = $block_size - (self::strlen($data) % $block_size);
			$data .= str_repeat(chr($pad), $pad);
		}
		// 生成密文，默认使用AES-128 CBC加密， 并将IV附在密文前面
		$data = (mcrypt_enc_get_modes_name($params['handle']) !== 'ECB')
			? $iv.mcrypt_generic($params['handle'], $data)
			: mcrypt_generic($params['handle'], $data);

		mcrypt_generic_deinit($params['handle']);
		if ($params['handle'] !== $this->_handle)
		{
			mcrypt_module_close($params['handle']);
		}

		return $data;
	}

	// hkdf SHA512 散列算法
	public function hkdf($key, $digest = 'sha512', $salt = NULL, $length = NULL, $info = '')
	{
		//... 参数合法性判断，略..

		// 长度填充
		self::strlen($salt) OR $salt = str_repeat("\0", $this->_digests[$digest]);
		
		// 注意 加密Key的盐为“encryption”, 散列Key的盐为“authentication”
		$prk = hash_hmac($digest, $key, $salt, TRUE);
		$key = '';
		for ($key_block = '', $block_index = 1; self::strlen($key) < $length; $block_index++)
		{
			$key_block = hash_hmac($digest, $key_block.$info.chr($block_index), $prk, TRUE);
			$key .= $key_block;
		}

		return self::substr($key, 0, $length);
	}
	// 解密略
```



### C++ 实现

* 使用CryptoPP++库(5.6.5) https://github.com/weidai11/cryptopp/releases/tag/CRYPTOPP_5_6_5
* 源文件无其它依赖，可直接编译 

> // 使用方法：
Encryption enc;
// 加密
std::string result = enc.Encrypt(text);
// 解密
std::string result = enc.Decrypt(text);

* 源代码

```
// file ci_encryption.h

#pragma once

#include <iostream>
#include <secblock.h>

using namespace CryptoPP;
using namespace std;


// 仅处理AES-128-CBC + HMAC SHA512
class Encryption{
protected:
	SecByteBlock _key;			// 保存的二进制原始Key bin
	size_t _digest_size;	// [sha512=64位], 384=>48, 256=>32, 224=>28
public:
	Encryption();
	~Encryption(){};

	// HKDF摘要算法,同ci的hkdf()函数
	int DeriveKeys(SecByteBlock& encrypt_key, SecByteBlock& hmac_key);

	// 与CI相同算法的加密与解密
	string Encrypt(const string& data);
	string Decrypt(const string& data);

};







// file ci_encryption.cpp

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
```
