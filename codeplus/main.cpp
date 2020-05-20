#include <iostream>
#include <string>
#include <sstream>
using namespace std;
#include "codeplus.h"
#include <string.h>

string pk = "3059301306072A8648CE3D020106082A8648CE3D03010703420004CFFD88C6718A056F53C52F59771B78DC3500F5D11F51565D81C8872550AE28E9198BC6A9FB1F30E0B54633B1DF71DF1FD93E6850C51666D040B0759C82B22218";
string priv = "3041020100301306072A8648CE3D020106082A8648CE3D03010704273025020101042098D012AC769EE493D982FA8E05692520CF377A5F6D86E56033F5FDCBE7671BBD";

string get_raw_string(string const& s)
{
	ostringstream out;
	out << '\"';
	out << std::hex;
	for (std::string::const_iterator it = s.begin(); it != s.end(); ++it)
	{
		out << "\\x" << (static_cast<short>(*it) & 0xff);
	}
	out << '\"';
	return out.str();
}

int main()
{
	//CodePlusString cpk, cprik;
	//cpk.iLen = pk.length();
	//memcpy(cpk.szBuf, pk.c_str(), cpk.iLen);

	//cprik.iLen = priv.length();
	//memcpy(cprik.szBuf, priv.c_str(), cprik.iLen);
	

	//cout << "public key: " << sspk.szBuf << endl;
	//cout << "private key: " << ssprik.szBuf << endl;

	std::string s1 = "a";

	for (int i = 0; i < 1; i++) {
		CodePlusString cpk, cprik;
		codeplus_generate(cpk, cprik);
		CodePlusString org;
		memcpy(org.szBuf, s1.c_str(), s1.length());
		org.iLen = s1.length();

		cout << "cpk : " << cpk.iLen << " data: " << cpk.szBuf << endl;
		CodePlusString enc;
		if (CODEPLUS_SUCCESS != codeplus_encrypt(org, cpk, enc))
		{
			cout << "encrypt ERROR : "<< get_raw_string(enc.szBuf) << enc.iLen << endl;
			return 1;
		}

		cout << "encrypt : "<< get_raw_string(enc.szBuf) << enc.iLen << endl;

		CodePlusString dec;
		if (CODEPLUS_SUCCESS != codeplus_decrypt(enc, cprik, dec))
		{
			cout << "decrypt ERROR : "<< get_raw_string(dec.szBuf) << dec.iLen << endl;
			return 1;
		}
		cout << "decrypt : "<< get_raw_string(dec.szBuf) << dec.iLen << endl;

		CodePlusString h;
		if (CODEPLUS_SUCCESS != codeplus_hash256(org, h))
		{
			cout << "hash ERROR : "<< get_raw_string(h.szBuf) << h.iLen << endl;
			return 1;
		}
		cout << "hash : "<< get_raw_string(h.szBuf) << h.iLen << endl;
		
		CodePlusString sign;
		if (CODEPLUS_SUCCESS != codeplus_sign(h, cprik, sign))
		{
			cout << "sign ERROR : "<< get_raw_string(sign.szBuf) << sign.iLen << endl;
			return 1;
		}
		
		cout << "sign: " << get_raw_string(sign.szBuf) << " size: " << sign.iLen << endl;
		cout << codeplus_verify(h, sign, cpk) << endl;
	}
	
	return 0;
}
