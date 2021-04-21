module tomcrypt

// int der_encode_integer(void *num,unsigned char *out,unsigned long *outlen);
fn C.der_encode_integer(byteptr, voidptr, &size_t) int
// ltc_asn1_list   sequence[3];unsigned long   three=3;LTC_SET_ASN1(sequence, 0, LTC_ASN1_IA5_STRING,    "hello", 5);LTC_SET_ASN1(sequence, 1, LTC_ASN1_SHORT_INTEGER, &three,  1);LTC_SET_ASN1(sequence, 2, LTC_ASN1_NULL,           NULL,   0);

pub fn der_encode_integer(int_bytes []byte) []byte {
	// TODO: check +4 is sufficient
	buf := []byte{len: int_bytes.len+4}
	buflen := size_t(buf.len)
	C.der_encode_integer(int_bytes.data, buf.data, &buflen)
	return buf[..int(buflen)]
}