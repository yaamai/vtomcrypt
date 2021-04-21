module tomcrypt

struct C.sha256_state {}
fn C.sha256_init(voidptr) int
fn C.sha256_process(voidptr, byteptr, size_t) int
fn C.sha256_done(voidptr, byteptr) int

pub fn sha256(data[]byte) []byte {
	state := C.sha256_state{}
	C.sha256_init(&state)
	C.sha256_process(&state, &data, data.len)

	out := []byte{len: 32}
	C.sha256_done(&state, out.data)
	return out
}