#include "codeplus.h"

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <cryptopp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include <cryptopp/files.h>
using CryptoPP::FileSource;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/asn.h>
#include <cryptopp/oids.h>
namespace ASN1 = CryptoPP::ASN1;

#include <cryptopp/eccrypto.h>
using CryptoPP::ECIES;

#include <cryptopp/sha.h>
using CryptoPP::SHA256;

#include <cryptopp/base64.h>
#include <cryptopp/aes.h>

int codeplus_generate(CodePlusString &pk, CodePlusString &privk)
{
    std::string sPrivateKey, sPublicKey;
	AutoSeededRandomPool prng(false, 256);
    CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey  ePrivateKey;
	ePrivateKey.Initialize(prng, ASN1::secp256r1());
	
    CryptoPP::ECIES<CryptoPP::ECP>::PublicKey   ePublicKey;
    ePrivateKey.MakePublicKey(ePublicKey);
    HexEncoder pubEncoder(new StringSink(sPublicKey));

    ePublicKey.DEREncode(pubEncoder);
    pubEncoder.MessageEnd();
    
    HexEncoder prvEncoder(new StringSink(sPrivateKey));
    ePrivateKey.DEREncode(prvEncoder);
    prvEncoder.MessageEnd();

    if (sPublicKey.length() > CODEPLUS_MAX || sPrivateKey.length() > CODEPLUS_MAX) {
        return ERR_DATA;
    }

    pk.iLen = sPublicKey.length();
    memcpy(pk.szBuf, sPublicKey.c_str(), pk.iLen);

    privk.iLen = sPrivateKey.length();
    memcpy(privk.szBuf, sPrivateKey.c_str(), privk.iLen);

    return CODEPLUS_SUCCESS;
}

int codeplus_encrypt(const CodePlusString s, const CodePlusString pk, CodePlusString &encs)
{
    if (s.iLen >= CODEPLUS_MAX || 0 >= pk.iLen) return ERR_DATA;

    std::string m_sPublicKey;
    m_sPublicKey.resize(pk.iLen);
    memcpy((void*)m_sPublicKey.c_str(), pk.szBuf, pk.iLen);

    StringSource pubString(m_sPublicKey, true, new HexDecoder);
    CryptoPP::ECIES<CryptoPP::ECP>::Encryptor enc(pubString);
    size_t uiCipherTextSize = enc.CiphertextLength(s.iLen);
    
    std::string sCipherText;
    sCipherText.resize(uiCipherTextSize);
    
    AutoSeededRandomPool prng;
    enc.Encrypt(prng, (const CryptoPP::byte *)(s.szBuf), s.iLen, (CryptoPP::byte *)(sCipherText.data()));

    encs.iLen = sCipherText.length();
    if (encs.iLen > sizeof(CodePlusString))return ERR_INNER;
    
    memcpy(encs.szBuf, sCipherText.c_str(), encs.iLen);
    
    return CODEPLUS_SUCCESS;
}

int codeplus_decrypt(const CodePlusString s, const CodePlusString pk, CodePlusString &decs)
{
    if (s.iLen > CODEPLUS_MAX || 0 >= pk.iLen) return ERR_DATA;

    std::string m_sPrivateKey;
    m_sPrivateKey.resize(pk.iLen);
    memcpy((void*)m_sPrivateKey.c_str(), pk.szBuf, pk.iLen);

    StringSource privString(m_sPrivateKey, true, new HexDecoder);
    CryptoPP::ECIES<CryptoPP::ECP>::Decryptor dec(privString);
    
    auto sPlainTextLen = dec.MaxPlaintextLength(s.iLen);
    
    std::string sDecryText;
    sDecryText.resize(sPlainTextLen);
    
    AutoSeededRandomPool prng;
    dec.Decrypt(prng, (const CryptoPP::byte *)s.szBuf, s.iLen, (CryptoPP::byte *)sDecryText.data());

    decs.iLen = sDecryText.length();
    if (decs.iLen > sizeof(CodePlusString))return ERR_INNER;
    
    memcpy(decs.szBuf, sDecryText.c_str(), decs.iLen);

    return CODEPLUS_SUCCESS;
}

int codeplus_hash256(const CodePlusString s, CodePlusString &h)
{
    SHA256 s2;
    unsigned char s2Buf[129] = {0};

    s2.CalculateDigest((CryptoPP::byte *)s2Buf, (CryptoPP::byte *)(s.szBuf), s.iLen);
    
    h.iLen = s2.DigestSize();
    memcpy(h.szBuf, s2Buf, h.iLen);
    
    return CODEPLUS_SUCCESS;
}

// convert the data to hex form
int codeplus_hexencode(const CodePlusString s, CodePlusString &hex)
{
    std::string encoded;

    StringSource ss(s.szBuf, true,
        new HexEncoder(
            new StringSink(encoded)
        )
    );

    hex.iLen = encoded.length();
    memcpy(hex.szBuf, encoded.c_str(), hex.iLen);

    return CODEPLUS_SUCCESS;
}

int codeplus_hexdecode(const CodePlusString s, CodePlusString &hex)
{
    std::string decoded = "";
    StringSource ss(s.szBuf, true,
        new HexDecoder(
            new StringSink(decoded)
        )
    );

    hex.iLen = decoded.length();
    memcpy(hex.szBuf, decoded.c_str(), hex.iLen);

    return CODEPLUS_SUCCESS;
}

int codeplus_sign(const CodePlusString h, const CodePlusString pk, CodePlusString &sign)
{
    if (h.iLen > CODEPLUS_MAX || pk.iLen > CODEPLUS_MAX) return ERR_DATA;

    std::string m_sPrivateKey;
    m_sPrivateKey.resize(pk.iLen);
    memcpy((void*)m_sPrivateKey.c_str(), pk.szBuf, pk.iLen);

    CryptoPP::AutoSeededRandomPool prng;

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PrivateKey privateKey;
    std::string exp = m_sPrivateKey.substr(70);
    
    CryptoPP::HexDecoder decoder;
    decoder.Put((CryptoPP::byte *)&exp[0], exp.size());
    decoder.MessageEnd();
    
    CryptoPP::Integer x;
    x.Decode(decoder, decoder.MaxRetrievable());
    privateKey.Initialize(CryptoPP::ASN1::secp256r1(), x);
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::Signer signer(privateKey);
    
    /* 
    std::string ssign;
    std::string hdata = h.szBuf;
    CryptoPP::StringSource s(hdata, true ,
                            new CryptoPP::SignerFilter(prng,
                                                        signer,
                                                        new CryptoPP::StringSink(ssign)
                                                        )
                            );
    */
    size_t siglen = signer.MaxSignatureLength();
    std::string signature(siglen, 0x00);
    siglen = signer.SignMessage(prng, 
                                (const CryptoPP::byte*)h.szBuf, 
                                h.iLen, 
                                (CryptoPP::byte *)&signature[0]);
    
    sign.iLen = siglen;
    memcpy(sign.szBuf, signature.c_str(), siglen);
    
    return CODEPLUS_SUCCESS;
}

int codeplus_verify(const CodePlusString h, const CodePlusString s, const CodePlusString pk)
{
    if (h.iLen >= CODEPLUS_MAX || s.iLen >= CODEPLUS_MAX || pk.iLen >= CODEPLUS_MAX)return ERR_DATA;

    std::string m_sPublicKey;
    m_sPublicKey.resize(pk.iLen);
    memcpy((void*)m_sPublicKey.c_str(), pk.szBuf, pk.iLen);

    std::string pt;
    pt = m_sPublicKey.substr(54);

    CryptoPP::HexDecoder decoder;
    decoder.Put((CryptoPP::byte *)&pt[0], pt.size());
    decoder.MessageEnd();

    CryptoPP::ECP::Point q;
    size_t len = decoder.MaxRetrievable();
    q.identity = false;
    q.x.Decode(decoder, len/2);
    q.y.Decode(decoder, len/2);

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PublicKey publicKey;
    publicKey.Initialize(CryptoPP::ASN1::secp256r1(), q);
    CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA1>::Verifier verifier(publicKey);
    
    //std::string sd;
    //int sdlen = s.iLen + h.iLen;
    //sd.resize(sdlen);
    //memcpy((void*)(sd.c_str()), s.szBuf, s.iLen);
    //memcpy((void*)(sd.c_str() + s.iLen), h.szBuf, h.iLen);
    bool result = verifier.VerifyMessage((const CryptoPP::byte*)h.szBuf, 
                                            h.iLen, 
                                            (const CryptoPP::byte*)s.szBuf, 
                                            s.iLen);
    /* 
    CryptoPP::StringSource ss(sd, true,
                                new CryptoPP::SignatureVerificationFilter(
                                    verifier,
                                    new CryptoPP::ArraySink((CryptoPP::byte *)&result, sizeof(result) )
                                    ));
    */
    if (result)
    {
        return CODEPLUS_SUCCESS;
    }

    return ERR_SIGN;
}
