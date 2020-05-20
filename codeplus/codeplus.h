#ifndef _CODEPLUS_INCLUDE_
#define _CODEPLUS_INCLUDE_

#define CODEPLUS_MAX     512

#define CODEPLUS_SUCCESS 0x01
#define ERR_PUBLICK      0xA0
#define ERR_PRIVATEKEY   0xA1
#define ERR_DATA         0xA2
#define ERR_INNER        0xA3
#define ERR_DATA_SIGN    0xA4
#define ERR_SIGN         0xA5


#ifdef __cplusplus  
extern "C"  //C++  
{  
#endif 

struct CodePlusString
{
	int iLen = 0;
	char szBuf[CODEPLUS_MAX] = {0};
};

// generate the public key and private key
int codeplus_generate(CodePlusString &pk, CodePlusString &privk);

// encrpt data by public key
int codeplus_encrypt(const CodePlusString s, const CodePlusString pk, CodePlusString &enc);

// decrypt the data by private key
int codeplus_decrypt(const CodePlusString s, const CodePlusString privk, CodePlusString &dec);

// get the data hash
int codeplus_hash256(const CodePlusString s, CodePlusString &h);

// convert the data to hex form
int codeplus_hexencode(const CodePlusString s, CodePlusString &hex);

int codeplus_hexdecode(const CodePlusString s, CodePlusString &dechex);

// get the signature
int codeplus_sign(const CodePlusString h, const CodePlusString privk, CodePlusString &s);

// verify the signature
int codeplus_verify(const CodePlusString h, const CodePlusString s, const CodePlusString pk);

#ifdef __cplusplus  
}  
#endif

#endif //_CODEPLUS_INCLUDE_
