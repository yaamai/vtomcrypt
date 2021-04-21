module tomcrypt

fn C.register_hash(voidptr) int
fn C.register_prng(voidptr) int
fn C.register_cipher(voidptr) int 

fn C.find_prng(charptr) int
fn C.find_hash(charptr) int
fn C.find_cipher(charptr) int

fn init() {
	if C.register_prng(&C.sprng_desc) == -1 {
		panic('Error registering sprng')
	}
	if C.register_hash(&C.sha1_desc) == -1 {
		panic('Error registering SHA1 hash')
	}
	if C.register_cipher(&C.aes_desc) == -1 {
		panic('Error registering aes cipher')
	}
	C.ltc_mp = C.ltm_desc
}