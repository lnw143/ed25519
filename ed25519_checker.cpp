#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>

namespace ed25519 {

#include "ed25519.h"

const std::string pub_key="...";
const std::string pri_key="...";

static int map[128];
void input(const std::string &src,int len,unsigned char *buf) {
	for(int i=0; i<len; ++i) buf[i]=map[src[i<<1]]<<4|map[src[i<<1|1]];
}

std::string output(int len,unsigned char *str) {
	std::stringstream ss;
	for(int i=0; i<len; ++i) ss<<std::hex<<std::setw(2)<<std::setfill('0')<<int(str[i]);
	return ss.str();
}

struct ED25519_Checker {
	unsigned char public_key[32], private_key[64];

	std::string sign(const std::string &message) {
		unsigned char signature[64];
		ed25519_sign(signature, reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), public_key, private_key);
		return output(64,signature);
	}
	
	bool verify(const std::string &sign,const std::string &message) {
		unsigned char signature[64];
		input(sign,64,signature);
		return ed25519_verify(signature, reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), public_key);
	}

	ED25519_Checker() {
		for(int i=0; i<10; ++i) map['0'+i]=i;
		for(int i='a'; i<'z'; ++i) map[i]=i-'a'+10;
		for(int i='A'; i<'Z'; ++i) map[i]=i-'A'+10;
		input(pub_key,32,public_key);
		input(pri_key,64,private_key);
	}
} checker;

}
