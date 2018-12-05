// Project math and Encryption functions
#include<vector>
#include<cstdlib>
#include<cstdint>
#include <string>
#include <cstring>
#include <ctime>
#include <cstdio>
#include<unistd.h>
#include "User.h"
//MIGHT NEED TO CHANGE LEFTROTATE1 FOR 28 BIT 
uint64_t des_leftrotate1(int64_t m){

    uint32_t up = 0;
    if(m >134217728)
        up = 1;
        
    m = m << 1;
    m += up;
    return m&(134217728*2-1);
}
uint64_t des_leftrotate(uint64_t m, uint64_t num){
	for (uint i = 0; i < num; ++i){
		m=des_leftrotate1(m);
	}
	return m;
}
uint64_t permute(uint64_t block, uint32_t* order, uint64_t result_len) {
    uint64_t i = 0;
    uint64_t mask = 1;
    uint64_t perm = 0;
    uint64_t holder = 0;
    
    // using a bitmask to grab the bits as they are needed
    for(i = 0; i< result_len; i++)
    {
        perm = perm << 1; // make space for next bit
        mask = mask <<  (order[i]-1); //move mask in the correct place
        holder = mask & block; // get bit
        if(holder != 0) perm = perm +1; // if it was a one in that position, add it to perm
        mask = 1; // reset mask
    }
    return perm;
}
uint64_t key_64_perm(uint64_t key){
	uint32_t order[56]= {57,49,41,33,25,17, 9, 1,
						58,50,42,34,26,18,10, 2,
						59,51,43,35,27,19,11, 3,
						60,52,44,36,63,55,47,39,
						31,23,15, 7,62,54,46,38,
						30,22,14, 6,61,53,45,37,
						29,21,13, 5,28,29,12, 4};
	return permute(key,order,56);
}
uint64_t key_56_perm(uint64_t key){
	uint32_t order[48]= {14,17,11,24, 1, 5, 3,28,
						15, 6,21,10,23,19,12, 4,
						26, 8,16, 7,27,20,13, 2,
						41,52,31,37,47,55,30,40,
						51,45,33,48,44,49,39,56,
						34,53,46,42,50,36,29,32};
	return permute(key,order,48);
}
uint64_t init_perm(uint64_t m){
	uint32_t order[64]={58,50,42,34,26,18,10, 2,
						60,52,44,36,28,20,12, 4,
						62,54,46,38,30,22,14, 6,
						64,56,48,40,32,24,16, 8,
						57,49,41,33,25,17, 9, 1,
						59,51,43,35,27,19,11, 3,
						61,53,45,37,29,21,13, 5,
						63,55,47,39,31,23,15, 7};

	return permute(m,order,64);
}
uint64_t inverse_init_perm(uint64_t m){
	uint32_t order[64]={40, 8,48,16,56,24,64,32,
						39, 7,47,15,55,23,63,31,
						38, 6,46,14,54,22,62,30,
						37, 5,45,13,53,21,61,29,
						36, 4,44,12,52,20,60,28,
						35, 3,43,11,51,19,59,27,
						34, 2,42,10,50,18,58,26,
						33, 1,41, 9,49,17,57,25};

	return permute(m,order,64);
}
uint64_t expansion_perm(uint32_t half_m){
	uint32_t order[48]={ 32, 1, 2, 3, 4, 5,
						 4, 5, 6, 7, 8, 9,
						 8, 9,10,11,12,13,
						12,13,14,15,16,17,
						16,17,18,19,20,21,
						20,21,22,23,24,25,
						24,25,26,27,28,29,
						28,29,30,31,32, 1};
	return permute(half_m,order,48);
}
uint32_t perm_32(uint32_t half_m){
	uint32_t order[32]={ 16, 7,20,21,29,12,28,17,
						 1,15,23,26, 5,18,31,10,
						 2, 8,24,14,32,27, 3, 9,
						19,13,39, 6,22,11, 4,25};
	return permute(half_m,order,32);
}
void get_keys(uint64_t* sub_keys,uint64_t key){
	//key is 64 bits
	//perform key_64_perm
	key=key_64_perm(key);
	//key is now 56 bits
	//split the key in to two 28 bit halfkeys.
	uint32_t left_key=536870911&key;
	uint32_t right_key=(key>>28);
	//table of how many shifts
	uint32_t shifts[16]={1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
	for (uint i = 0; i < 16; ++i){
		left_key=des_leftrotate(left_key,shifts[i]);
		right_key=des_leftrotate(right_key,shifts[i]);
		//combine the two,

		uint64_t temp_key=(left_key<<28) + right_key;

		sub_keys[i]=key_56_perm(temp_key);
	}
}
uint32_t f_box(uint32_t right,uint64_t key){
	uint64_t expand=expansion_perm(right);
	uint32_t s_boxes[8][4][16]={{{14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7},
								{ 0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8},
								{ 4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0},
								{15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13}},

							   {{15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10},
							   	{ 3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5},
							   	{ 0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15},
							   	{13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9}},
							  
							   {{10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8},
							   	{13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1},
							   	{13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7},
							   	{ 1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12}},

							   {{ 7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15},
							   	{13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9},
							   	{10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4},
							   	{ 3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14}},

							   {{ 2,12, 5, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9},
							    {14,11, 2,12, 5, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6},
							    { 4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14},
							    {11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3}},

							   {{12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11},
							    {10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8},
							    { 9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6},
							    { 4, 3, 2,13, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13}},

							   {{ 4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1},
							    {13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 6, 1},
							    { 1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2},
							    { 6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12}},

							   {{13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7},
							    { 1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2},
							    { 7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8},
							    { 2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11}}};

	expand=expand^key;
	//split expand in 8 6 bit chunks
	uint32_t chunk[8];
	for (int i = 0; i < 8; ++i){
		chunk[i]=expand&63;
		expand=expand>>6;
	}
	//send each chunk to an sbox.
	uint64_t output=0;
	for (int i = 0; i < 8; ++i){
		uint32_t outer=(chunk[i]&1)+((chunk[i]&32)>>4);
		uint32_t inner=(chunk[i]&30)>>1;

		output+=s_boxes[i][outer][inner]<<(4*(7-i));
	}
	return perm_32(output);
}

uint64_t des_encrypt(uint64_t plain_text, uint64_t key){
	//Initial Permutation
	
	plain_text=init_perm(plain_text);
	//split plaintext uinto left and right
	uint32_t right=plain_text&4294967295;
	uint32_t left=(plain_text>>32)&4294967295;
	uint32_t temp;

	uint64_t sub_keys[16];
	get_keys(sub_keys,key);
	//16 rounds
	for (uint i = 0; i < 16; ++i){
		uint64_t round_key=sub_keys[i];
		temp=right;
		right=left^f_box(right,round_key);
		left=temp;
	}
	temp=right;
	right=left;
	left=temp;
	uint64_t left2=left;
	uint64_t output=right+(left2<<32);
	output=inverse_init_perm(output);
	return output;
}

int do_des_encrypt(char* buf, int num_bytes, char* loc, uint64_t key) {
    uint64_t block;
    uint64_t cipher;
    int bytes_left = num_bytes;
    int i = 0;
    char buffer[8];
    memset(buffer, 0, 8);
    while(bytes_left > 7) {
        memcpy(&block, &buf[i], 8);
        cipher = des_encrypt(block, key);
        memcpy(&loc[i], &cipher, 8);
        bytes_left-= 8;
        i+=8;
    }
    if(bytes_left > 0) {
        memcpy(buffer, &buf[i], bytes_left);
        memcpy(&block, buffer, 8);
        cipher = des_encrypt(block, key);
        memcpy(&loc[i], &cipher, 8);
        i+=8;
    }
    return i;
}

uint64_t des_decrypt(uint64_t plain_text, uint64_t key){
	//Initial Permutation
	plain_text=init_perm(plain_text);
	//split plaintext uinto left and right
	uint32_t right=plain_text&4294967295;
	uint32_t left=(plain_text>>32)&4294967295;
	uint32_t temp;
	
	//split the main key in to two 28 bit pieces
	uint64_t sub_keys[16];
	get_keys(sub_keys,key);
	//16 rounds
	for (uint i = 0; i < 16; ++i){
		uint64_t round_key=sub_keys[15-i];

		temp=right;
		right=left^f_box(right,round_key);
		left=temp;

	}
	temp=right;
	right=left;
	left=temp;
	uint64_t left2=left;
	uint64_t output=right+(left2<<32);
	output=inverse_init_perm(output);
	return output;
}

int do_des_decrypt(char* buf, int num_bytes, char* loc, uint64_t key) {
    uint64_t block;
    uint64_t cipher;
    int bytes_left = num_bytes;
    int i = 0;
    char buffer[8];
    memset(buffer, 0, 8);
    while(bytes_left > 7) {
        memcpy(&cipher, &buf[i], 8);
        block = des_decrypt(cipher, key);
        memcpy(&loc[i], &block, 8);
        bytes_left-= 8;
        i+=8;
    }
    if(bytes_left > 0) {
        memcpy(buffer, &buf[i], bytes_left);
        memcpy(&cipher, buffer, 8);
        block = des_decrypt(cipher, key);
        memcpy(&loc[i], &block, 8);
        i+=8;
    }
    return i;
}

int64_t leftrotate1(int64_t m){

    uint64_t up = 0;
    if(m <0)
        up = 1;
        
    m = m << 1;
    m += up;
    return m;
}
int64_t leftrotate(int64_t m, uint64_t num){
	for (uint64_t i = 0; i < num; ++i){
		m=leftrotate1(m);
	}
	return m;
}
void SHA_1(char* m,uint32_t num_bytes, uint32_t* hash){
	int32_t h0 = 0x67452301;
	int32_t h1 = 0xEFCDAB89;
	int32_t h2 = 0x98BADCFE;
	int32_t h3 = 0x10325476;
	int32_t h4 = 0xC3D2E1F0;
	int64_t ml=num_bytes;
	char* msg;
	int64_t m2=ml%64;
	int64_t m3;
	//exactly right. No padding nessisary
	if(m2==56){
		msg = new char[num_bytes+100];
		memset(msg, num_bytes+100, 0);
		m3 = num_bytes;
	}
	//not enough add 56-ml chars to m.
	else if(m2<56){
		msg = new char[num_bytes + (56-m2)+100];
		memset(msg, num_bytes + (56-m2)+100, 0);	//use 0 as the padding
		m3 = num_bytes+56-m2;
	}

	else if(m2>56){
		msg = new char[num_bytes + (120-m2)+100];
		memset(msg, num_bytes + (120-m2)+100, 0);	//use 0 as the padding
		m3 = num_bytes + 120 -m2;
	}
	memcpy(msg, m, num_bytes);
	uint64_t const total_length=m3;
	memcpy(&msg[total_length],&ml,8);
	
	//msg is some multiple of 512 bits
	uint64_t num_chunks=(total_length+8)/64;
	for (uint64_t i = 0; i < num_chunks; ++i){		//break 64 bytes into 16 4 byte pieces

		//turn these 16 chunks into 80  4 byte chunks
		int32_t extended[80];
		//cpy the first 16 chunks in.
		memcpy(extended,&msg[64*i],64);
		for (uint64_t j = 16; j < 80; ++j){

			int32_t w1,w2,w3,w4;
			w1=extended[j-3];
			w2=extended[j-8];
			w3=extended[j-14];
			w4=extended[j-16];
			int32_t f= w1^w2^w3^w4;
			f=leftrotate(f,1);
			extended[j]=f;
		}

		int32_t a=h0;
		int32_t b=h1;
		int32_t c=h2;
		int32_t d=h3;
		int32_t e=h4;
		

		for (uint64_t j = 0; j < 80; ++j){
			
			int32_t w=extended[j];
			int32_t f;
			int32_t k;
			if(j<20){
				f=(b&c) |((~b)&d);
				k=0x5A827999;
			}
			else if(j<40){
				f=b^c^d;
				k=0x6ED9EBA1;
			}
			else if(j<60){
				f=(b&c)|(b&d)^(c&d);
				k=0x8F1BBCDC;
			}
			else if(j<40){
				f=b^c^d;
				k=0xCA62C1D6;
			}
			int64_t temp=(leftrotate(a,5)+f+e+k+w) % 4294967296;
			e=d;
			d=c;
			c=(leftrotate(b,30));
			b=a;
			a=temp;
		}
		h0+=a;
		h1+=b;
		h2+=c;
		h3+=d;
		h4+=e;
	}
 	int32_t hh[5]={h0,h1,h2,h3,h4};
 	memcpy(hash,hh,20);
 	delete [] msg;
}

uint32_t exp_mod( uint32_t base,  uint32_t exp,  uint32_t mod){
    uint64_t sol = base;
    uint64_t cur_exp = exp;
    while(cur_exp > 1)
    {
        if(cur_exp %2 == 0)
        {
            sol = (sol*sol) % mod;
            cur_exp = cur_exp/2;
        }
        else
        {
            uint32_t ender = exp_mod(sol, cur_exp-1, mod);
            return (sol*ender) % mod;
        }
    }
    return sol;
}
int check_prime( uint32_t candidate){
    //printf("CANDIDATE: %u\n", candidate);
     uint32_t exp = candidate - 1;
     uint32_t a; 
     uint32_t result;
     int r = 0;
     int i, j;
    while(exp%2 == 0)
    {
        r++;
        exp = exp/2;
        //printf("exp: %u\n", exp);
    }
    
    if(r == 0)
        return 0;
    //printf("r = %u\n", r);
    
    for(i = 0; i< 16; i++)
    {
        a = (rand() % (candidate-4)) + 2;
        //printf("CHECKING a = %u\n", a);
        //printf("MODDING: %u, %u, %u\n", a[i], exp, candidate);
        result = exp_mod(a, exp, candidate);
        //printf("result: %u\n", result);
        if(result == 1 || (result == candidate-1))
            continue;
        else
        {
            for(j = 0; j<r-1; j++)
            {
                result = exp_mod(result, 2, candidate);
                //printf("result: %u\n", result);
                if(result == candidate -1)
                {
                    break;
                }
            }
            if(result == candidate -1)
                continue;
            return 0;
        }
    }
    return 1;
}
uint32_t generate_prime( uint32_t max){
    uint32_t mod;
    if(max == 0)
        mod = RAND_MAX-1;
    else
        mod = max;
        
    uint32_t holder = rand() % mod;
    uint32_t check = holder << 1;
    check = check +1;
    
    while(!check_prime(holder)) {
        holder = rand() % mod;
        uint32_t check = holder << 1;
        check = check +1;
    }
    return holder;
}

uint32_t find_prime_root(uint32_t p, std::vector<uint32_t>& result_facs)
{
    uint32_t left = p-1;
    int num = 1;
    std::vector<uint32_t> factors;
    int check = 2;
    while(!check_prime(left)) {
        if(left%check ==0) {
            factors.push_back(check);
            left = left/check;
        }
        else {
            check = check+1;
        }
    }
    int i;
    result_facs.push_back(factors[0]);
    for(i = 1; i< factors.size(); i++) {
        if(factors[i] != result_facs[num-1]) {
            result_facs.push_back(factors[i]);
            num++;
        }   
    }
    factors.clear();
    
    for(i =0; i<num; i++) {
        factors.push_back((p-1)/result_facs[i]);
    }
    
    int is_true = 0;
    u_int prim_root = 2;
    while(!is_true || prim_root == (p-1)) {
        is_true = 1;
        for(i=0; i<num; i++) {
            if(exp_mod(prim_root, factors[i], p) == 1) {
                is_true = 0;
                
            }
        }
        if(is_true)
            return prim_root;
        prim_root++;
    }
    return 0;
}
uint64_t Euclid( int64_t a,  int64_t b, int64_t& inverse){
	//if they're backwards flip them.
	if (a<b){
		uint64_t t=b;
		b=a;
		a=t;
	}
	int64_t a2=a;
	std::vector<int64_t> q;



	uint64_t r= a%b;
	q.push_back(a/b);
	while(r!=0){
		a=b;
		b=r;
		r=a%b;
		q.push_back(a/b);
		if(a<0||b<0){
			std::cout<<"NEGATIVE ERROR"<<std::endl;
		}
	}



	//extended 
	int64_t p0=0;
	int64_t p1=1;
	for (uint64_t i = 0; i < q.size()-1; ++i){
		int64_t t=p1;
		p1=(p0-p1*q[i])%a2;
		p0=t;
	}
	if (p1<0){
		p1+=a2;
	}
	inverse=p1;
	return b;
}
void RSA_key_maker( uint64_t& n, uint64_t& pub,  uint64_t& priv){
	//Find two primes p,q
	uint32_t p,q;
	p=generate_prime(65535);
	q=generate_prime(65535);
	n=p*q;

	uint64_t phi=(p-1)*(q-1);
	//std::cout << "phi: " << phi << std::endl;
	//Find a coprime to phi between 1 and phi.
	//Random? start low go high? start hi go low? double check if it comes out "wierd"
	bool found=false;
	 int64_t e=rand() % (phi -2);
	 int64_t inverse;
	while(!found){
		if(e>phi){
			std::cout<<"ERROR";
		}
		if(Euclid(phi,e, inverse)==1){
			found=true;
		}
		else{
			e=rand()%(phi-2);
		}
	}

	pub=e;
	priv=inverse;
	if (priv<0){
		std::cout<<"ERROR NEGATIVE KEY"<<std::endl;
	}
	if(pub<0){
		std::cout<<"ERROR NEGATIVE KEY";
	}
}
uint64_t RSA_Encrypt_Decrypt( uint64_t m,  uint64_t e_d,  uint64_t n){
	uint64_t a=exp_mod(m,e_d,n);
	if(a<0){
		return a+n;
	}
	else if(a>n){
		return a-n;
	}
	else
		return a;
}

void semantic_RSA_encrypt(uint32_t m,uint32_t e,uint32_t n, uint32_t& e1,uint32_t& e2){
	uint32_t h[5];
	uint32_t r=rand()%n;
	e1=RSA_Encrypt_Decrypt(r,e,n);
	char r_s[20];
	int len = sprintf(r_s, "%u", r);
	
	SHA_1(r_s, len,h);
	uint32_t hash;
	memcpy(&hash,h,4);
	e2=hash^m;
	// std::cout<<e1<<' '<<e2<<std::endl;
}
uint64_t semantic_RSA_decrypt(uint64_t e1,uint64_t e2,uint64_t d,uint64_t n){
	// std::cout<<e1<<' '<<e2<<' '<<d<<' '<<n<<std::endl;
	uint64_t r=RSA_Encrypt_Decrypt(e1,d,n);
	if(r > n) {
		std::cout << "encryption error" << std::endl;
	}
	char r_s[20];
	int len = sprintf(r_s, "%lu", r);
	uint32_t h[5];
	SHA_1(r_s, len,h);
	uint64_t hash;
	memcpy(&hash,h,4);
	return e2^hash;
	
}
int do_RSA_encrypt(char* buf, int num_bytes, char* loc, uint32_t n, uint32_t e_d) {
    uint32_t block= 0;
    uint32_t cipher =0;
    int bytes_left = num_bytes;
    int i = 0;
    char buffer[2];
    memset(buffer, 0, 2);
    while(bytes_left > 1) {
        block = 0;
        cipher = 0;
        memcpy(&block, &buf[i], 2);
        //std::cout << "block: "<<block << std::endl;
        cipher = RSA_Encrypt_Decrypt(block, e_d, n);
        //std::cout << "cipher:" << cipher << std::endl;
        memcpy(&loc[2*i], &cipher, 4);
        bytes_left-= 2;
        i+=2;
    }
    if(bytes_left > 0) {
        memcpy(&buffer, &buf[i], bytes_left);
        memcpy(&block, buffer, 2);
        cipher = RSA_Encrypt_Decrypt(block, e_d, n);
        memcpy(&loc[2*i], &cipher, 4);
        i+=2;
    }
    return 2*i;
}

int do_RSA_decrypt(char* buf, int num_bytes, char* loc, uint32_t n, uint32_t e_d) {
	uint32_t block= 0;
    uint32_t cipher =0;
    uint16_t small;
    int bytes_left = num_bytes;
    int i = 0;
    char buffer[4];
    memset(buffer, 0, 4);
    while(bytes_left > 3) {
        block = 0;
        cipher = 0;
        memcpy(&block, &buf[2*i], 4);
        std::cout << "block: "<<block << std::endl;
        cipher = RSA_Encrypt_Decrypt(block, e_d, n);
        if(cipher > 65535) {
        	std::cout << "decrypt error" << std::endl;
        }
        std::cout << "cipher:" << cipher << std::endl;
        small = cipher;
        memcpy(&loc[i], &cipher, 2);
        bytes_left-= 4;
        i+=2;
    }
    if(bytes_left > 0) {
        memcpy(&buffer, &buf[2*i], bytes_left);
        memcpy(&block, buffer, 4);
        cipher = RSA_Encrypt_Decrypt(block, e_d, n);
        memcpy(&loc[i], &cipher, 4);
        i+=2;
    }
    return i;
}
int do_SEM_encrypt(char* buf, int num_bytes, char* loc, uint32_t n, uint32_t e_d) {
    uint32_t block = 0;
    uint32_t e1, e2;
    e1 = e2 = 0;
    int bytes_left = num_bytes;
    int i = 0;
    char buffer[4];
    memset(buffer, 0, 4);
    while(bytes_left > 3) {
        memcpy(&block, &buf[i], 4);
        semantic_RSA_encrypt(block, e_d, n, e1, e2);
        memcpy(&loc[i*2], &e1, 4);
        memcpy(&loc[(2*i)+4], &e2, 4);
        bytes_left-= 4;
        i+=4;
    }
    if(bytes_left > 0) {
        memcpy(buffer, &buf[i], bytes_left);
        memcpy(&block, buffer, 4);
        semantic_RSA_encrypt(block, e_d, n, e1, e2);
        memcpy(&loc[2*i], &e1, 4);
        memcpy(&loc[(2*i)+4], &e2, 4);
        i+=4;
    }
    return 2*i;
}

int do_SEM_decrypt(char* buf, int num_bytes, char* loc, uint64_t n, uint64_t e_d) {
    uint32_t block;
    uint32_t e1, e2;
    int bytes_left = num_bytes;
    int i = 0;
    char buffer[8];
    memset(buffer, 0, 8);
    while(bytes_left > 7) {
        memcpy(&e1, &buf[2*i], 4);
        memcpy(&e2, &buf[(2*i)+4], 4);
        block = semantic_RSA_decrypt(e1, e2, e_d, n);
        memcpy(&loc[i], &block, 4);
        bytes_left-= 8;
        i+=4;
    }
    if(bytes_left > 0) {
    	std::cout << "Something is probably wrong..." << std::endl;
        memcpy(buffer, &buf[i], bytes_left);
        memcpy(&e1, buffer, 4);
        memcpy(&e2, &buffer[4], 4);
        block = semantic_RSA_decrypt(e1, e2, e_d, n);
        memcpy(&loc[i], &block, 4);
        i+=4;
    }
    return i;
}

uint32_t DH_generator(uint64_t& N, uint64_t& pub, uint64_t& priv) {
    N = generate_prime(0);
    std::vector<uint32_t> facs;
    uint32_t root = find_prime_root(N, facs);
    
    prime_root_find:
    uint32_t q = generate_prime(N);
    for(uint32_t i = 0; i < facs.size(); i++) {
        if(q == facs[i]) {
            goto prime_root_find;
        }
    }
    root = exp_mod(root, q, N);
    
    priv = rand() %N;
    pub = exp_mod(root, priv, N);
    return root;
}

int e_and_send(char* buf, int num_bytes, std::string code, User& user, int comm_sock, char* put) {
    uint64_t N, e;
    uint64_t des;
    char* encrypt;
    int bytes_written;
    int pad_len;
    uint32_t MAC[5];
    char mac[20];
    char* buffer = new char[num_bytes +21];
    memcpy(buffer, buf, num_bytes);
    memset(&buffer[num_bytes], 0, 1);
    if(!code.compare("RSA")) {
    	pad_len = num_bytes%2;
    	for(int i = 0; i < pad_len; i++) {
    		buf[num_bytes + i] = '\0';
    	}
    	SHA_1(buf, num_bytes+pad_len, MAC);
    	memcpy(mac, MAC, 20);
        user.get_rsa_send(N, e);
        encrypt= new char[2*(num_bytes+21)+ 500];
        bytes_written = do_RSA_encrypt(buffer, num_bytes, encrypt, N, e);
        des = do_RSA_encrypt(mac, 20, &encrypt[bytes_written], N, e); 
        if(put != NULL) {
        	memcpy(put, encrypt, bytes_written + des);
        }
        else {
        	bytes_written = send(comm_sock, encrypt, bytes_written + des, 0);
        }
        delete [] encrypt;
        delete [] buffer;
        return bytes_written + des;
    }
    else if(!code.compare("SEM")) {
    	pad_len = num_bytes%4;
    	for(int i = 0; i < pad_len; i++) {
    		buffer[num_bytes + i] = '\0';
    	}
    	SHA_1(buffer, num_bytes+pad_len, MAC);
    	
    	memcpy(mac, MAC, 20);
    	std::cout << "MAC" << std::endl;
    	for(int i = 0; i < 20; i++) {
    		printf("%d ", mac[i]);
    	}
    	std::cout << std::endl;
        user.get_sem_send(N, e);
        encrypt = new char[2*(num_bytes +21)+500];
        std::cout << N << " " << e << std::endl;
        std::cout << "BEFORE ENCRYPT: " << num_bytes<<std::endl;
        for(int i = 0; i < num_bytes; i++) {
        	printf("%d ", buffer[i]);
        }
        std::cout<< std::endl;
        bytes_written = do_SEM_encrypt(buffer, num_bytes, encrypt, N, e);
        des = do_SEM_encrypt(mac, 20, &encrypt[bytes_written], N, e);
        std::cout << "AFTER ENCRYPT: " << bytes_written + des <<std::endl;
        for(int i = 0; i < bytes_written + des; i++) {
        	printf("%d ", encrypt[i]);
        }
        std::cout<< std::endl;
        if(put != NULL) {
        	memcpy(put, encrypt, bytes_written + des);
        }
        else {
        	bytes_written = send(comm_sock, encrypt, bytes_written + des, 0);
        }
        delete [] encrypt;
        delete [] buffer;
        return bytes_written + des;
    }
    else if(!code.compare("DES")) {
        user.get_des(des);
       /* 
       	make sure that encrypt has divisible by 8 bytes. 
        if char buf[13]="ADD PADDING!"
        need to add 3 so char[16]encrypt
        MY ATTEMPT AT SOLUTION TO PADDING
        int x= (20+num_bytes)%8;
        int padding_needed=8-x;
        encrypt= new char[num_bytes + 20 + padding_needed;
        look at crypt_test for example of sorts.
        */
        pad_len = 8 - (num_bytes%8);
    	for(int i = 0; i < pad_len; i++) {
    		buffer[num_bytes + i] = '\0';
    	}
    	SHA_1(buffer, num_bytes+pad_len, MAC);
    	memcpy(mac, MAC, 20);
        encrypt = new char[500+ num_bytes + 20];
        bytes_written = do_des_encrypt(buffer, num_bytes, encrypt, des);
        N = do_des_encrypt(mac, 20, &encrypt[bytes_written], des);
        if(put != NULL) {
        	memcpy(put, encrypt, bytes_written + N);
        }
        else {
        	bytes_written = send(comm_sock, encrypt, bytes_written + N, 0);
        }
        delete [] encrypt; 
        delete [] buffer;
        return bytes_written + N;
    }
    else {
    	delete [] buffer;
        return false;
    }
}

int d_and_check(char* buf, int num_bytes, char* msg, std::string code, User& user) {
    uint64_t N, d;
    uint64_t des;
    int bytes_written;
    uint32_t MAC[5];
    uint32_t OMAC[5];
    char mac[24];
    char* msg_mac;
    memset(mac, 0, 24);
    if(!code.compare("RSA")) {
    	std::cout << "GOT IN RSA" << std::endl;
        user.get_rsa_recv(N, d);
        bytes_written = do_RSA_decrypt(buf, num_bytes, msg, N, d);
        msg_mac = &msg[bytes_written -20];
        SHA_1(msg, bytes_written-20, MAC);
        memcpy(mac, MAC, 20);
        if(memcmp(mac, msg_mac, 20)!= 0) {
            std::cerr << "Something went wrong in RSA, shutting down..." << std::endl;
            //close(comm_sock);
            //exit(1);
            return -1;
        }
        else
            return bytes_written -20;
    }
    else if(!code.compare("SEM")) {
    	std::cout << "GOT IN SEM" << std::endl;
        user.get_sem_recv(N, d);
        std::cout << N << " " << d << std::endl;
        std::cout << "BEFORE DECRYPTION: " << num_bytes<< std::endl;
        for(int i = 0; i < num_bytes; i++) {
        	printf("%d ", buf[i]);
        }
        std::cout << std::endl;
        bytes_written = do_SEM_decrypt(buf, num_bytes, msg, N, d);
        std::cout << "AFTER DECRYPTION: "<< bytes_written << std::endl;
        for(int i = 0; i < bytes_written; i++) {
        	printf("%d ", msg[i]);
        }
        std::cout << std::endl;
        msg_mac = &msg[bytes_written-20];
        SHA_1(msg, bytes_written - 20, MAC);
        memcpy(mac, MAC, 20);
        if(memcmp(mac, msg_mac, 20) != 0) {
            std::cerr << "Something went wrong in SEM, shutting down..." << std::endl;
            //close(comm_sock);
            //exit(1);
            return -1;
        }
        else
            return bytes_written - 20;
    }
    else if(!code.compare("DES")) {
    	std::cout << "GOT INTO DES" << std::endl;
        user.get_des(des);
        bytes_written = do_des_decrypt(buf, num_bytes, msg, des);
        msg_mac = &msg[bytes_written-24];
        memcpy(OMAC, msg_mac, 20);
        SHA_1(msg, bytes_written-24, MAC);
        if(memcmp(MAC, OMAC, 20) != 0) {
            std::cerr << "Something went wrong in DES, shutting down..." << std::endl;
            //close(comm_sock);
            //exit(1);
            return -1;
        }
        else
            return bytes_written - 24;
    }
    return -1;
}

