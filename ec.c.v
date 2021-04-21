module tomcrypt

struct C.Ecc_key {}
// int ecc_make_key(prng_state *prng,int  wprng,int  keysize,ecc_key *key);
fn C.ecc_make_key(voidptr, int, int, voidptr) int
// int ecc_export(unsigned char *out,unsigned long *outlen,int  type,ecc_key *key);
fn C.ecc_export(voidptr, &size_t, int, voidptr) int
// int ecc_import(const unsigned char *in,unsigned long  inlen,ecc_key *key);
fn C.ecc_import(voidptr, size_t, voidptr) int
// int ecc_sign_hash_rfc7518(const unsigned char *in,unsigned long  inlen,unsigned char *out,unsigned long *outlen,prng_state *prng,int  wprng,ecc_key *key);
fn C.ecc_sign_hash_rfc7518(voidptr, size_t, voidptr, &size_t, voidptr, int, voidptr) int
// int ecc_verify_hash_rfc7518(const unsigned char *sig,unsigned long  siglen,const unsigned char *hash,unsigned long  hashlen,int *stat,ecc_key *key);
fn C.ecc_verify_hash_rfc7518(voidptr, size_t, voidptr, size_t, &int, voidptr) int

struct EccKey {
	key C.Ecc_key
}

pub fn ecc_make_key(key_size int) ?EccKey {
	prng := C.find_prng("sprng")

	key := EccKey{}
	rc := C.ecc_make_key(0, prng, int(key_size/8), &key.key)
	if rc != 0 {
		return error("failed to ecc_make_key()")
	}
	return key
}

pub fn ecc_import(key_bytes[]byte) ?EccKey {
	key := EccKey{}
	rc := C.ecc_import(key_bytes.data, key_bytes.len, &key.key)
	if rc != 0 {
		return error("failed to ecc_import()")
	}
	return key
}

pub fn (k EccKey) export(priv bool) ?[]byte {
	buf := []byte{len: C.ECC_BUF_SIZE}
	buflen := size_t(buf.len)
	is_priv := if priv {1} else {0}
	rc := C.ecc_export(buf.data, &buflen, is_priv, &k.key)
	if rc != 0 {
		return error("failed to ecc_export()")
	}

	return buf[..int(buflen)]
}

pub fn (k EccKey) sign_rfc7518(data []byte) ?[]byte {
	prng := C.find_prng("sprng")
	buf := []byte{len: data.len}
	buflen := size_t(buf.len)

	rc := C.ecc_sign_hash_rfc7518(&data, data.len, buf.data, &buflen, 0, prng, &k.key)
	if rc != 0 {
		return error("failed to ecc_sign_hash_rfc7518()")
	}

	return buf[..int(buflen)]
}

pub fn (k EccKey) verify_rfc7518(data []byte, sig []byte) ?bool {
	stat := int(0)

	rc := C.ecc_verify_hash_rfc7518(sig.data, sig.len, data.data, data.len, &stat, &k.key)
	if rc != 0 {
		return error("failed to ecc_verify_hash_rfc7518()")
	}

	return (int(stat) != 0)
}