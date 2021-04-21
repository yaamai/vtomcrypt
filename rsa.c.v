module tomcrypt

struct C.Rsa_key {}

struct RsaKey {
	key C.Rsa_key
}

// int rsa_import(const unsigned char *in,unsigned long  inlen,rsa_key *key);
fn C.rsa_import(byteptr, C.size_t, voidptr) int

pub fn load_rsa_key(k []byte) RsaKey {
	r := RsaKey {}
	res := C.rsa_import(k.data, C.size_t(k.len), &r.key)
	if res != 0 {
		panic('unable to import key $res')
	}

	return r
}

// int rsa_encrypt_key(const unsigned char *in,unsigned long  inlen,unsigned char *out,unsigned long *outlen,const unsigned char *lparam,unsigned long  lparamlen,prng_state *prng,int  prng_idx,int  hash_idx,rsa_key *key);
fn C.rsa_encrypt_key(byteptr, C.size_t, voidptr, &C.size_t, voidptr, C.size_t, voidptr, int, int, voidptr) int

pub fn (key RsaKey) sha1_encrypt_key_into(@in []byte, mut out []byte) {
	hash_idx := C.find_hash('sha1')
	prng_idx := C.find_prng("sprng")

	size := C.size_t(out.len)

	res := C.rsa_encrypt_key(
		@in.data,
		C.size_t(@in.len),
		out.data,
		&size,
		C.NULL,
		C.size_t(0),
		C.NULL,
		prng_idx,
		hash_idx,
		&key.key
	)

	if res != 0 {
		panic('unable to encrypt @in $res')
	}
}


pub fn (key RsaKey) sha1_encrypt_key(@in []byte) []byte {
	mut out := []byte{len:@in.len*16}

	key.sha1_encrypt_key_into(@in, mut out)

	return out
}