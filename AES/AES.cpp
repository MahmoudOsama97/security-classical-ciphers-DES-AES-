#include<bitset>
#include<vector>
#include<algorithm>
#include<string>
#include <iostream>
#include <iomanip>
#include <sstream>

using namespace std;
using uc = unsigned char;
using vc = std::vector<uc>;
using matc = std::vector<vc>;
using ll = unsigned long long;
using vi = std::vector<int>;
using ui = unsigned int;

const uc SBOX[] = { 0x63 ,0x7c ,0x77 ,0x7b ,0xf2 ,0x6b ,0x6f ,0xc5 ,0x30 ,0x01 ,0x67 ,0x2b ,0xfe ,0xd7 ,0xab ,0x76
 ,0xca ,0x82 ,0xc9 ,0x7d ,0xfa ,0x59 ,0x47 ,0xf0 ,0xad ,0xd4 ,0xa2 ,0xaf ,0x9c ,0xa4 ,0x72 ,0xc0
 ,0xb7 ,0xfd ,0x93 ,0x26 ,0x36 ,0x3f ,0xf7 ,0xcc ,0x34 ,0xa5 ,0xe5 ,0xf1 ,0x71 ,0xd8 ,0x31 ,0x15
 ,0x04 ,0xc7 ,0x23 ,0xc3 ,0x18 ,0x96 ,0x05 ,0x9a ,0x07 ,0x12 ,0x80 ,0xe2 ,0xeb ,0x27 ,0xb2 ,0x75
 ,0x09 ,0x83 ,0x2c ,0x1a ,0x1b ,0x6e ,0x5a ,0xa0 ,0x52 ,0x3b ,0xd6 ,0xb3 ,0x29 ,0xe3 ,0x2f ,0x84
 ,0x53 ,0xd1 ,0x00 ,0xed ,0x20 ,0xfc ,0xb1 ,0x5b ,0x6a ,0xcb ,0xbe ,0x39 ,0x4a ,0x4c ,0x58 ,0xcf
 ,0xd0 ,0xef ,0xaa ,0xfb ,0x43 ,0x4d ,0x33 ,0x85 ,0x45 ,0xf9 ,0x02 ,0x7f ,0x50 ,0x3c ,0x9f ,0xa8
 ,0x51 ,0xa3 ,0x40 ,0x8f ,0x92 ,0x9d ,0x38 ,0xf5 ,0xbc ,0xb6 ,0xda ,0x21 ,0x10 ,0xff ,0xf3 ,0xd2
 ,0xcd ,0x0c ,0x13 ,0xec ,0x5f ,0x97 ,0x44 ,0x17 ,0xc4 ,0xa7 ,0x7e ,0x3d ,0x64 ,0x5d ,0x19 ,0x73
 ,0x60 ,0x81 ,0x4f ,0xdc ,0x22 ,0x2a ,0x90 ,0x88 ,0x46 ,0xee ,0xb8 ,0x14 ,0xde ,0x5e ,0x0b ,0xdb
 ,0xe0 ,0x32 ,0x3a ,0x0a ,0x49 ,0x06 ,0x24 ,0x5c ,0xc2 ,0xd3 ,0xac ,0x62 ,0x91 ,0x95 ,0xe4 ,0x79
 ,0xe7 ,0xc8 ,0x37 ,0x6d ,0x8d ,0xd5 ,0x4e ,0xa9 ,0x6c ,0x56 ,0xf4 ,0xea ,0x65 ,0x7a ,0xae ,0x08
 ,0xba ,0x78 ,0x25 ,0x2e ,0x1c ,0xa6 ,0xb4 ,0xc6 ,0xe8 ,0xdd ,0x74 ,0x1f ,0x4b ,0xbd ,0x8b ,0x8a
 ,0x70 ,0x3e ,0xb5 ,0x66 ,0x48 ,0x03 ,0xf6 ,0x0e ,0x61 ,0x35 ,0x57 ,0xb9 ,0x86 ,0xc1 ,0x1d ,0x9e
 ,0xe1 ,0xf8 ,0x98 ,0x11 ,0x69 ,0xd9 ,0x8e ,0x94 ,0x9b ,0x1e ,0x87 ,0xe9 ,0xce ,0x55 ,0x28 ,0xdf
 ,0x8c ,0xa1 ,0x89 ,0x0d ,0xbf ,0xe6 ,0x42 ,0x68 ,0x41 ,0x99 ,0x2d ,0x0f ,0xb0 ,0x54 ,0xbb ,0x16 };

const uc ISBOX[] = {
0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

const vi SHIFTROWPERM({
	0,5,10,15
	,4,9,14,3
	,8,13,2,7
	,12,1,6,11
	});
const vi ISHIFTROWPERM({
	0,13,10,7
	,4,1,14,11
	,8,5,2,15
	,12,9,6,3
	});

const ll MOD = (1 << 8) | (1 << 4) | (1 << 3) | (1 << 1) | (1 << 0);

const uc MIXCOL[][4] =
{
	{02, 03, 01, 01},
	{01, 02, 03, 01},
	{01, 01, 02, 03},
	{03, 01, 01, 02}
};

const uc IMIXCOL[][4] =
{
	{0x0E, 0x0B, 0x0D, 0x09},
	{0x09, 0x0E, 0x0B, 0x0D},
	{0x0D, 0x09, 0x0E, 0x0B},
	{0x0B, 0x0D, 0x09, 0x0E}
};





void ARK(vc& state, vc& key) {
	for (int i = 0; i < state.size(); i++) {
		state[i] = state[i] ^ key[i];
	}
}
void SB(vc& state, const uc sbox[] = SBOX) {//default is encryption
	vc tempState(state.size());
	for (int i = 0; i < state.size(); i++)
			tempState[i] = sbox[state[i]];
	state = tempState;
}
void SR(vc& state, const vi& shifter = SHIFTROWPERM) {
	vc tempState(state.size());
	for (int i = 0; i < state.size(); i++)
		tempState[i] = state[shifter[i]];
	state = tempState;
}
uc mod(ll n) {
	while (n & (~255ll)) {//as long as n is not 8 bit
		int shift = 64-9;  ll p = 1ll << 63;
		while ((n & p) == 0ll)
		{ 
			shift--, p >>= 1; 
		}
		n = n ^ (MOD << (shift));
	}
	return uc(n);
}
uc getMul(uc a, uc b) {
	ll mx = max(a, b), mn = min(a,b);
	ll mul = 1;
	ll ans = 0;
	int shift = 0;
	while (mul <= mn) {
		if (mul & mn) {//if a bit in mn is 1
			ans ^= mx << shift;//xor the mx shifted by the order of this bit in mn
		}
		shift++;
		mul <<= 1;
	}
	return mod(ans);
}
void MC(vc& state, const uc mat [][4]= MIXCOL) {
	uc tempState[4][4];
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			tempState[j][i] = state[4 * i + j];
	uc ans[4][4];

	for (int i = 0; i < 4; i++) {
		ans[0][i] = getMul(tempState[0][i], mat[0][0]) ^ getMul(tempState[1][i], mat[0][1]) ^ getMul(tempState[2][i], mat[0][2]) ^ getMul(tempState[3][i], mat[0][3]);
		ans[1][i] = getMul(tempState[0][i], mat[1][0]) ^ getMul(tempState[1][i], mat[1][1]) ^ getMul(tempState[2][i], mat[1][2]) ^ getMul(tempState[3][i], mat[1][3]);
		ans[2][i] = getMul(tempState[0][i], mat[2][0]) ^ getMul(tempState[1][i], mat[2][1]) ^ getMul(tempState[2][i], mat[2][2]) ^ getMul(tempState[3][i], mat[2][3]);
		ans[3][i] = getMul(tempState[0][i], mat[3][0]) ^ getMul(tempState[1][i], mat[3][1]) ^ getMul(tempState[2][i], mat[3][2]) ^ getMul(tempState[3][i], mat[3][3]);
	}
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			state[4 * i + j] = ans[j][i];
}

void wordtovc(ui word[4], vc& output) {
	output.resize(4 * 4);
	for (int i = 0; i < 4; i++) {
		output[4 * i + 3] = word[i];//lsb of word goes in fourth row
		word[i] >>= 8;
		output[4 * i + 2] = word[i];
		word[i] >>= 8;
		output[4 * i + 1] = word[i];
		word[i] >>= 8;
		output[4 * i] = word[i];
	}
}

ui auxF(ui oldword, int index, const uc sbox[] =SBOX) {
	oldword = (oldword << 8) | (oldword >> 24);//rot word

	ui b1 = uc(oldword) , b2 = uc(oldword >> 8), b3 = uc(oldword >> 16), b4 = uc(oldword >> 24);
	b1 = sbox[b1];
	b2 = sbox[b2];
	b3 = sbox[b3];
	b4 = sbox[b4] ^ mod(1U << (index));//rcon
	ui newword = b1 | b2 << 8 | b3 << 16 | b4 << 24;//sub word

	return newword;
}
void setnextkey(ui key[4], ui oldkey[4], int index, const uc sbox[] = SBOX) {//both key and oldkey are 4 words
	key[0] = oldkey[0] ^ auxF(oldkey[3], index);
	for (int i = 1; i < 4; i++)
		key[i] = key[i - 1] ^ oldkey[i];
}



void outText(vc&);
vc AES(ll pMSB, ll pLSB , ll kMSB, ll kLSB, bool encrypt = 1) {
	//hold init key in an array of words (ll)
	ui initkey[4] = {ui(kMSB >> 32), ui(kMSB), ui(kLSB >> 32), ui(kLSB)};
	ui uikeys[10][4];//array of 10 4worded keys
	//create keys
	for (int i = 0; i < 10; i++)
		if (i)
			setnextkey(uikeys[i], uikeys[i - 1], i);//takes current key to fill it and previous key
		else
			setnextkey(uikeys[i], initkey,i);//takes initial key for the first word
	vc keys[11];
	for (int i = 0; i < 11; i++) {
		if (i) {
			wordtovc(uikeys[i - 1], keys[i]);//other keys
		}
		else
			wordtovc(initkey, keys[i]);//init key
	}

	if (!encrypt) {//swap keys on decrypt
		vc tempState[11];
		for (int i = 0; i < 11; i++)
			tempState[i] = keys[10 - i];
		for (int i = 0; i < 11; i++)
			keys[i] = tempState[i];
	}


	vc state(16);
	for (int i = 0; i < 8; i++) {
		state[i] = pMSB >> (64 - 8);
		pMSB <<= 8;
	}
	for (int i = 0; i < 8; i++) {
		state[i + 8] = pLSB >> (64 - 8);
		pLSB <<= 8;
	}
	
	//state now is correct
	
	if (encrypt) {
		ARK(state, keys[0]);
	}
	else {//decryption
		ARK(state, keys[0]);
		SR(state, ISHIFTROWPERM);
		SB(state, ISBOX);
	}
	for (int i = 1; i < 10; i++) {
		if (encrypt) {
			SB(state);
			SR(state);
			MC(state);
			ARK(state, keys[i]);
		}
		else {
			ARK(state, keys[i]);
			MC(state, IMIXCOL);
			SR(state, ISHIFTROWPERM);
			SB(state, ISBOX);	
		}
	}
	if (encrypt) {
		SB(state);
		SR(state);
		ARK(state, keys[10]);
	}
	else {
		ARK(state, keys[10]);
	}

	return state;
}
void outText(vc& state) {
	cout << setfill('0') << setw(2) << uppercase;
	for (int i = 0; i < state.size(); i++)
		cout << setfill('0') << setw(2) << hex << int(state[i]);
	cout << endl;
}
void strToState(string num, ll& msb, ll& lsb) {
	stringstream s1(num.substr(0, 16)), s2(num.substr(16,16));
	s1 >> hex >> msb;
	s2 >> hex >> lsb;
}
int main()
{

	while (1) {
		cout << "0:decryption and 1:encryption" << endl;
		int choice;
		cin >> choice;
		ll kmsb = 0;
		ll klsb = 0;
		ll pmsb = 0;
		ll plsb = 0;
		if (choice == 0 || choice == 1) {
			cout <<"key:"<< endl;
			string key; cin >> key;
			strToState(key, kmsb, klsb);
			cout << "text"<< endl;
			string plain; cin >> plain;
			strToState(plain, pmsb, plsb);
			auto state = AES(pmsb, plsb, kmsb, klsb, choice);
			cout << "out:"<< endl;
			outText(state);
		}
		else {
			cout << "invalid input";
		}
	}

}