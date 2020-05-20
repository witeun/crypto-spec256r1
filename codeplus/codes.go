package codes

/*
#cgo CFLAGS: -I./codeplus
#cgo linux LDFLAGS: -L ./codeplus -l codeplus
#cgo linux LDFLAGS: -Wl,-rpath="/mnt/f/code/go/src/go-codeplus/codes/codeplus"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CODEPLUS_MAX 512
#define CODEPLUS_SUCCESS 0x01
#define ERR_PUBLICK      0xA0
#define ERR_PRIVATEKEY   0xA1
#define ERR_DATA         0xA2
#define ERR_INNER        0xA3
#define ERR_DATA_SIGN    0xA4
#define ERR_SIGN         0xA5

typedef struct _CodePlusString
{
	int iLen;
	char szBuf[CODEPLUS_MAX];
}CodePlusString;

int codeplus_generate(CodePlusString *pk, CodePlusString *privk);
int codeplus_encrypt(CodePlusString s, CodePlusString pk, CodePlusString *enc);
int codeplus_decrypt(CodePlusString s, CodePlusString privk, CodePlusString *dec);
int codeplus_hash256(CodePlusString s, CodePlusString *h);
int codeplus_sign(CodePlusString h, CodePlusString privk, CodePlusString *sign);
int codeplus_verify(CodePlusString h, CodePlusString s, CodePlusString pk);
void to_codestring(CodePlusString *s, char* data, int ilen)
{
	s->iLen = ilen;
	memcpy(s->szBuf, data, ilen);
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func Verify(h []byte, s []byte, pk []byte) (res int, err error) {
	if len(h) <= 0 || len(s) <= 0 || len(pk) <= 0 {
		return 1, fmt.Errorf("input error.")
	}

	sh := C.CString(string(h[:]))
	ss := C.CString(string(s[:]))
	spk := C.CString(string(pk[:]))
	var chash, cpk, cs C.CodePlusString

	C.to_codestring(&chash, sh, C.int(len(h)))
	C.to_codestring(&cpk, spk, C.int(len(pk)))
	C.to_codestring(&cs, ss, C.int(len(s)))

	C.free(unsafe.Pointer(sh))
	C.free(unsafe.Pointer(ss))
	C.free(unsafe.Pointer(spk))

	if C.CODEPLUS_SUCCESS != C.codeplus_verify(chash, cs, cpk) {
		return 1, fmt.Errorf("verify unpass.")
	}

	return 0, nil
}

func Sign(h []byte, privk []byte) (s []byte, err error) {
	if len(h) <= 0 || len(privk) <= 0 {
		return []byte{}, fmt.Errorf("input error.")
	}

	ss := C.CString(string(h[:]))
	sprivk := C.CString(string(privk[:]))
	var cdata, cprivk, cs C.CodePlusString
	C.to_codestring(&cdata, ss, C.int(len(h)))
	C.to_codestring(&cprivk, sprivk, C.int(len(privk)))
	C.free(unsafe.Pointer(ss))
	C.free(unsafe.Pointer(sprivk))

	if C.CODEPLUS_SUCCESS != C.codeplus_sign(cdata, cprivk, &cs) {
		return []byte{}, fmt.Errorf("signature error.")
	}

	s, err = ctoByte(cs)
	if nil != err {
		return []byte{}, fmt.Errorf("sign in c failed.")
	}

	return s, nil
}

func Hash(data string) (h []byte, err error) {
	if len(data) <= 0 {
		return []byte{}, fmt.Errorf("input error.")
	}

	s := C.CString(data)
	var cdata, ch C.CodePlusString
	C.to_codestring(&cdata, s, C.int(len(data)))
	C.free(unsafe.Pointer(s))

	if C.CODEPLUS_SUCCESS != C.codeplus_hash256(cdata, &ch) {
		return []byte{}, fmt.Errorf("hash calc error.")
	}

	h, err = ctoByte(ch)
	if nil != err {
		return []byte{}, fmt.Errorf("hash in c failed.")
	}

	return h, nil
}

func Decrypt(data string, privk string) (dec []byte, err error) {
	if len(data) <= 0 || len(privk) <= 0 {
		return []byte{}, fmt.Errorf("input error.")
	}

	s := C.CString(data)
	sprivk := C.CString(privk)
	var cdata, cprivk, cdec C.CodePlusString
	C.to_codestring(&cdata, s, C.int(len(data)))
	C.to_codestring(&cprivk, sprivk, C.int(len(privk)))
	C.free(unsafe.Pointer(s))
	C.free(unsafe.Pointer(sprivk))

	if C.CODEPLUS_SUCCESS != C.codeplus_decrypt(cdata, cprivk, &cdec) {
		return []byte{}, fmt.Errorf("decrypt error.")
	}

	dec, err = ctoByte(cdec)
	if nil != err {
		return []byte{}, fmt.Errorf("decrypt in c failed.")
	}

	return dec, nil
}

func Encrypt(data string, pk string) (enc []byte, err error) {
	if len(data) <= 0 || len(pk) <= 0 {
		return []byte{}, fmt.Errorf("input error.")
	}

	s := C.CString(data)
	spk := C.CString(pk)
	var cdata, cpk, cenc C.CodePlusString
	C.to_codestring(&cdata, s, C.int(len(data)))
	C.to_codestring(&cpk, spk, C.int(len(pk)))

	C.free(unsafe.Pointer(s))
	C.free(unsafe.Pointer(spk))

	if C.CODEPLUS_SUCCESS != C.codeplus_encrypt(cdata, cpk, &cenc) {
		return []byte{}, fmt.Errorf("encrypt error.")
	}

	enc, err = ctoByte(cenc)
	if err != nil {
		return []byte{}, fmt.Errorf("encrypt in c failed.")
	}

	return enc, nil
}

func Generate() (pk []byte, privk []byte, err error) {
	var cpk, cprivk C.CodePlusString
	if C.CODEPLUS_SUCCESS != C.codeplus_generate(&cpk, &cprivk) {
		return []byte{}, []byte{}, fmt.Errorf("generate in c failed.")
	}

	pk, err = ctoByte(cpk)
	if nil != err {
		return []byte{}, []byte{}, err
	}

	privk, err = ctoByte(cprivk)
	if nil != err {
		return pk, []byte{}, err
	}

	return pk, privk, nil
}

func ctoByte(cst C.CodePlusString) (data []byte, err error) {
	if cst.iLen <= 0 {
		return []byte{}, fmt.Errorf("c struct error.")
	}

	for i := 0; i < int(cst.iLen); i++ {
		data = append(data, uint8(cst.szBuf[i]))
	}

	return data, nil
}
