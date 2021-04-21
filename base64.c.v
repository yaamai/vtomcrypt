module tomcrypt

fn C.base64url_strict_decode(charptr, size_t, voidptr, &size_t) int
pub fn base64url_strict_decode(indata string) ?[]byte {
	buf := []byte{len: indata.len*2}
	buflen := size_t(buf.len)
	rc := C.base64url_strict_decode(indata.bytes().data, indata.len, buf.data, &buflen)
	if rc != 0 {
		return error("failed base64_url decode")
	}
	return buf[..int(buflen)]
}