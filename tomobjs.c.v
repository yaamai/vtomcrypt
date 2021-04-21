module tomcrypt

#flag -D LTM_DESC
#flag -D USE_LTM
#flag -D LTC_SOURCE
#flag -I @VMODROOT/libtomcrypt/src/headers
#flag -I @VMODROOT/libtommath
#include "tomcrypt.h"

#flag @VMODROOT/libtomcrypt/src/ciphers/aes/aes.o
#flag @VMODROOT/libtomcrypt/src/ciphers/anubis.o
#flag @VMODROOT/libtomcrypt/src/ciphers/blowfish.o 
#flag @VMODROOT/libtomcrypt/src/ciphers/camellia.o
#flag @VMODROOT/libtomcrypt/src/ciphers/cast5.o
#flag @VMODROOT/libtomcrypt/src/ciphers/des.o
#flag @VMODROOT/libtomcrypt/src/ciphers/kasumi.o
#flag @VMODROOT/libtomcrypt/src/ciphers/khazad.o 
#flag @VMODROOT/libtomcrypt/src/ciphers/kseed.o
#flag @VMODROOT/libtomcrypt/src/ciphers/multi2.o
#flag @VMODROOT/libtomcrypt/src/ciphers/noekeon.o
#flag @VMODROOT/libtomcrypt/src/ciphers/rc2.o
#flag @VMODROOT/libtomcrypt/src/ciphers/rc5.o 
#flag @VMODROOT/libtomcrypt/src/ciphers/rc6.o
#flag @VMODROOT/libtomcrypt/src/ciphers/safer/safer.o
#flag @VMODROOT/libtomcrypt/src/ciphers/safer/saferp.o
#flag @VMODROOT/libtomcrypt/src/ciphers/skipjack.o 
#flag @VMODROOT/libtomcrypt/src/ciphers/twofish/twofish.o
#flag @VMODROOT/libtomcrypt/src/ciphers/xtea.o
#flag @VMODROOT/libtomcrypt/src/encauth/ccm/ccm_add_aad.o 
#flag @VMODROOT/libtomcrypt/src/encauth/ccm/ccm_add_nonce.o
#flag @VMODROOT/libtomcrypt/src/encauth/ccm/ccm_done.o
#flag @VMODROOT/libtomcrypt/src/encauth/ccm/ccm_init.o 
#flag @VMODROOT/libtomcrypt/src/encauth/ccm/ccm_memory.o
#flag @VMODROOT/libtomcrypt/src/encauth/ccm/ccm_process.o
#flag @VMODROOT/libtomcrypt/src/encauth/ccm/ccm_reset.o 
#flag @VMODROOT/libtomcrypt/src/encauth/ccm/ccm_test.o
#flag @VMODROOT/libtomcrypt/src/encauth/chachapoly/chacha20poly1305_add_aad.o 
#flag @VMODROOT/libtomcrypt/src/encauth/chachapoly/chacha20poly1305_decrypt.o
#flag @VMODROOT/libtomcrypt/src/encauth/chachapoly/chacha20poly1305_done.o 
#flag @VMODROOT/libtomcrypt/src/encauth/chachapoly/chacha20poly1305_encrypt.o
#flag @VMODROOT/libtomcrypt/src/encauth/chachapoly/chacha20poly1305_init.o 
#flag @VMODROOT/libtomcrypt/src/encauth/chachapoly/chacha20poly1305_memory.o
#flag @VMODROOT/libtomcrypt/src/encauth/chachapoly/chacha20poly1305_setiv.o 
#flag @VMODROOT/libtomcrypt/src/encauth/chachapoly/chacha20poly1305_setiv_rfc7905.o 
#flag @VMODROOT/libtomcrypt/src/encauth/chachapoly/chacha20poly1305_test.o
#flag @VMODROOT/libtomcrypt/src/encauth/eax/eax_addheader.o 
#flag @VMODROOT/libtomcrypt/src/encauth/eax/eax_decrypt.o
#flag @VMODROOT/libtomcrypt/src/encauth/eax/eax_decrypt_verify_memory.o
#flag @VMODROOT/libtomcrypt/src/encauth/eax/eax_done.o 
#flag @VMODROOT/libtomcrypt/src/encauth/eax/eax_encrypt.o
#flag @VMODROOT/libtomcrypt/src/encauth/eax/eax_encrypt_authenticate_memory.o 
#flag @VMODROOT/libtomcrypt/src/encauth/eax/eax_init.o
#flag @VMODROOT/libtomcrypt/src/encauth/eax/eax_test.o
#flag @VMODROOT/libtomcrypt/src/encauth/gcm/gcm_add_aad.o 
#flag @VMODROOT/libtomcrypt/src/encauth/gcm/gcm_add_iv.o
#flag @VMODROOT/libtomcrypt/src/encauth/gcm/gcm_done.o
#flag @VMODROOT/libtomcrypt/src/encauth/gcm/gcm_gf_mult.o 
#flag @VMODROOT/libtomcrypt/src/encauth/gcm/gcm_init.o
#flag @VMODROOT/libtomcrypt/src/encauth/gcm/gcm_memory.o
#flag @VMODROOT/libtomcrypt/src/encauth/gcm/gcm_mult_h.o 
#flag @VMODROOT/libtomcrypt/src/encauth/gcm/gcm_process.o
#flag @VMODROOT/libtomcrypt/src/encauth/gcm/gcm_reset.o
#flag @VMODROOT/libtomcrypt/src/encauth/gcm/gcm_test.o 
#flag @VMODROOT/libtomcrypt/src/encauth/ocb/ocb_decrypt.o
#flag @VMODROOT/libtomcrypt/src/encauth/ocb/ocb_decrypt_verify_memory.o 
#flag @VMODROOT/libtomcrypt/src/encauth/ocb/ocb_done_decrypt.o
#flag @VMODROOT/libtomcrypt/src/encauth/ocb/ocb_done_encrypt.o
#flag @VMODROOT/libtomcrypt/src/encauth/ocb/ocb_encrypt.o 
#flag @VMODROOT/libtomcrypt/src/encauth/ocb/ocb_encrypt_authenticate_memory.o
#flag @VMODROOT/libtomcrypt/src/encauth/ocb/ocb_init.o
#flag @VMODROOT/libtomcrypt/src/encauth/ocb/ocb_ntz.o 
#flag @VMODROOT/libtomcrypt/src/encauth/ocb/ocb_shift_xor.o
#flag @VMODROOT/libtomcrypt/src/encauth/ocb/ocb_test.o
#flag @VMODROOT/libtomcrypt/src/encauth/ocb/s_ocb_done.o 
#flag @VMODROOT/libtomcrypt/src/encauth/ocb3/ocb3_add_aad.o
#flag @VMODROOT/libtomcrypt/src/encauth/ocb3/ocb3_decrypt.o
#flag @VMODROOT/libtomcrypt/src/encauth/ocb3/ocb3_decrypt_last.o 
#flag @VMODROOT/libtomcrypt/src/encauth/ocb3/ocb3_decrypt_verify_memory.o
#flag @VMODROOT/libtomcrypt/src/encauth/ocb3/ocb3_done.o 
#flag @VMODROOT/libtomcrypt/src/encauth/ocb3/ocb3_encrypt.o
#flag @VMODROOT/libtomcrypt/src/encauth/ocb3/ocb3_encrypt_authenticate_memory.o 
#flag @VMODROOT/libtomcrypt/src/encauth/ocb3/ocb3_encrypt_last.o
#flag @VMODROOT/libtomcrypt/src/encauth/ocb3/ocb3_init.o
#flag @VMODROOT/libtomcrypt/src/encauth/ocb3/ocb3_int_ntz.o 
#flag @VMODROOT/libtomcrypt/src/encauth/ocb3/ocb3_int_xor_blocks.o
#flag @VMODROOT/libtomcrypt/src/encauth/ocb3/ocb3_test.o
#flag @VMODROOT/libtomcrypt/src/hashes/blake2b.o 
#flag @VMODROOT/libtomcrypt/src/hashes/blake2s.o
#flag @VMODROOT/libtomcrypt/src/hashes/chc/chc.o
#flag @VMODROOT/libtomcrypt/src/hashes/helper/hash_file.o 
#flag @VMODROOT/libtomcrypt/src/hashes/helper/hash_filehandle.o
#flag @VMODROOT/libtomcrypt/src/hashes/helper/hash_memory.o 
#flag @VMODROOT/libtomcrypt/src/hashes/helper/hash_memory_multi.o
#flag @VMODROOT/libtomcrypt/src/hashes/md2.o
#flag @VMODROOT/libtomcrypt/src/hashes/md4.o
#flag @VMODROOT/libtomcrypt/src/hashes/md5.o 
#flag @VMODROOT/libtomcrypt/src/hashes/rmd128.o
#flag @VMODROOT/libtomcrypt/src/hashes/rmd160.o
#flag @VMODROOT/libtomcrypt/src/hashes/rmd256.o
#flag @VMODROOT/libtomcrypt/src/hashes/rmd320.o
#flag @VMODROOT/libtomcrypt/src/hashes/sha1.o 
#flag @VMODROOT/libtomcrypt/src/hashes/sha2/sha224.o
#flag @VMODROOT/libtomcrypt/src/hashes/sha2/sha256.o
#flag @VMODROOT/libtomcrypt/src/hashes/sha2/sha384.o
#flag @VMODROOT/libtomcrypt/src/hashes/sha2/sha512.o 
#flag @VMODROOT/libtomcrypt/src/hashes/sha2/sha512_224.o
#flag @VMODROOT/libtomcrypt/src/hashes/sha2/sha512_256.o
#flag @VMODROOT/libtomcrypt/src/hashes/sha3.o
#flag @VMODROOT/libtomcrypt/src/hashes/sha3_test.o 
#flag @VMODROOT/libtomcrypt/src/hashes/tiger.o
#flag @VMODROOT/libtomcrypt/src/hashes/whirl/whirl.o
#flag @VMODROOT/libtomcrypt/src/mac/blake2/blake2bmac.o 
#flag @VMODROOT/libtomcrypt/src/mac/blake2/blake2bmac_file.o
#flag @VMODROOT/libtomcrypt/src/mac/blake2/blake2bmac_memory.o 
#flag @VMODROOT/libtomcrypt/src/mac/blake2/blake2bmac_memory_multi.o
#flag @VMODROOT/libtomcrypt/src/mac/blake2/blake2bmac_test.o
#flag @VMODROOT/libtomcrypt/src/mac/blake2/blake2smac.o 
#flag @VMODROOT/libtomcrypt/src/mac/blake2/blake2smac_file.o
#flag @VMODROOT/libtomcrypt/src/mac/blake2/blake2smac_memory.o 
#flag @VMODROOT/libtomcrypt/src/mac/blake2/blake2smac_memory_multi.o
#flag @VMODROOT/libtomcrypt/src/mac/blake2/blake2smac_test.o
#flag @VMODROOT/libtomcrypt/src/mac/f9/f9_done.o 
#flag @VMODROOT/libtomcrypt/src/mac/f9/f9_file.o
#flag @VMODROOT/libtomcrypt/src/mac/f9/f9_init.o
#flag @VMODROOT/libtomcrypt/src/mac/f9/f9_memory.o
#flag @VMODROOT/libtomcrypt/src/mac/f9/f9_memory_multi.o 
#flag @VMODROOT/libtomcrypt/src/mac/f9/f9_process.o
#flag @VMODROOT/libtomcrypt/src/mac/f9/f9_test.o
#flag @VMODROOT/libtomcrypt/src/mac/hmac/hmac_done.o
#flag @VMODROOT/libtomcrypt/src/mac/hmac/hmac_file.o 
#flag @VMODROOT/libtomcrypt/src/mac/hmac/hmac_init.o
#flag @VMODROOT/libtomcrypt/src/mac/hmac/hmac_memory.o
#flag @VMODROOT/libtomcrypt/src/mac/hmac/hmac_memory_multi.o 
#flag @VMODROOT/libtomcrypt/src/mac/hmac/hmac_process.o
#flag @VMODROOT/libtomcrypt/src/mac/hmac/hmac_test.o
#flag @VMODROOT/libtomcrypt/src/mac/omac/omac_done.o
#flag @VMODROOT/libtomcrypt/src/mac/omac/omac_file.o 
#flag @VMODROOT/libtomcrypt/src/mac/omac/omac_init.o
#flag @VMODROOT/libtomcrypt/src/mac/omac/omac_memory.o
#flag @VMODROOT/libtomcrypt/src/mac/omac/omac_memory_multi.o 
#flag @VMODROOT/libtomcrypt/src/mac/omac/omac_process.o
#flag @VMODROOT/libtomcrypt/src/mac/omac/omac_test.o
#flag @VMODROOT/libtomcrypt/src/mac/pelican/pelican.o 
#flag @VMODROOT/libtomcrypt/src/mac/pelican/pelican_memory.o
#flag @VMODROOT/libtomcrypt/src/mac/pelican/pelican_test.o
#flag @VMODROOT/libtomcrypt/src/mac/pmac/pmac_done.o 
#flag @VMODROOT/libtomcrypt/src/mac/pmac/pmac_file.o
#flag @VMODROOT/libtomcrypt/src/mac/pmac/pmac_init.o
#flag @VMODROOT/libtomcrypt/src/mac/pmac/pmac_memory.o 
#flag @VMODROOT/libtomcrypt/src/mac/pmac/pmac_memory_multi.o
#flag @VMODROOT/libtomcrypt/src/mac/pmac/pmac_ntz.o
#flag @VMODROOT/libtomcrypt/src/mac/pmac/pmac_process.o 
#flag @VMODROOT/libtomcrypt/src/mac/pmac/pmac_shift_xor.o
#flag @VMODROOT/libtomcrypt/src/mac/pmac/pmac_test.o
#flag @VMODROOT/libtomcrypt/src/mac/poly1305/poly1305.o 
#flag @VMODROOT/libtomcrypt/src/mac/poly1305/poly1305_file.o
#flag @VMODROOT/libtomcrypt/src/mac/poly1305/poly1305_memory.o 
#flag @VMODROOT/libtomcrypt/src/mac/poly1305/poly1305_memory_multi.o
#flag @VMODROOT/libtomcrypt/src/mac/poly1305/poly1305_test.o
#flag @VMODROOT/libtomcrypt/src/mac/xcbc/xcbc_done.o 
#flag @VMODROOT/libtomcrypt/src/mac/xcbc/xcbc_file.o
#flag @VMODROOT/libtomcrypt/src/mac/xcbc/xcbc_init.o
#flag @VMODROOT/libtomcrypt/src/mac/xcbc/xcbc_memory.o 
#flag @VMODROOT/libtomcrypt/src/mac/xcbc/xcbc_memory_multi.o
#flag @VMODROOT/libtomcrypt/src/mac/xcbc/xcbc_process.o
#flag @VMODROOT/libtomcrypt/src/mac/xcbc/xcbc_test.o 
#flag @VMODROOT/libtomcrypt/src/math/fp/ltc_ecc_fp_mulmod.o
#flag @VMODROOT/libtomcrypt/src/math/gmp_desc.o
#flag @VMODROOT/libtomcrypt/src/math/ltm_desc.o
#flag @VMODROOT/libtomcrypt/src/math/multi.o 
#flag @VMODROOT/libtomcrypt/src/math/radix_to_bin.o
#flag @VMODROOT/libtomcrypt/src/math/rand_bn.o
#flag @VMODROOT/libtomcrypt/src/math/rand_prime.o
#flag @VMODROOT/libtomcrypt/src/math/tfm_desc.o
#flag @VMODROOT/libtomcrypt/src/misc/adler32.o 
#flag @VMODROOT/libtomcrypt/src/misc/base64/base64_decode.o
#flag @VMODROOT/libtomcrypt/src/misc/base64/base64_encode.o
#flag @VMODROOT/libtomcrypt/src/misc/burn_stack.o 
#flag @VMODROOT/libtomcrypt/src/misc/compare_testvector.o
#flag @VMODROOT/libtomcrypt/src/misc/crc32.o
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt.o
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_argchk.o 
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_cipher_descriptor.o
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_cipher_is_valid.o 
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_constants.o
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_find_cipher.o 
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_find_cipher_any.o
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_find_cipher_id.o 
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_find_hash.o
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_find_hash_any.o 
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_find_hash_id.o
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_find_hash_oid.o 
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_find_prng.o
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_fsa.o
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_hash_descriptor.o 
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_hash_is_valid.o
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_inits.o 
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_ltc_mp_descriptor.o
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_prng_descriptor.o 
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_prng_is_valid.o
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_prng_rng_descriptor.o 
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_register_all_ciphers.o
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_register_all_hashes.o 
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_register_all_prngs.o
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_register_cipher.o 
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_register_hash.o
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_register_prng.o
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_sizes.o 
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_unregister_cipher.o
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_unregister_hash.o 
#flag @VMODROOT/libtomcrypt/src/misc/crypt/crypt_unregister_prng.o
#flag @VMODROOT/libtomcrypt/src/misc/error_to_string.o
#flag @VMODROOT/libtomcrypt/src/misc/hkdf/hkdf.o 
#flag @VMODROOT/libtomcrypt/src/misc/hkdf/hkdf_test.o
#flag @VMODROOT/libtomcrypt/src/misc/mem_neq.o
#flag @VMODROOT/libtomcrypt/src/misc/pk_get_oid.o
#flag @VMODROOT/libtomcrypt/src/misc/pkcs5/pkcs_5_1.o 
#flag @VMODROOT/libtomcrypt/src/misc/pkcs5/pkcs_5_2.o
#flag @VMODROOT/libtomcrypt/src/misc/pkcs5/pkcs_5_test.o
#flag @VMODROOT/libtomcrypt/src/misc/zeromem.o
#flag @VMODROOT/libtomcrypt/src/modes/cbc/cbc_decrypt.o 
#flag @VMODROOT/libtomcrypt/src/modes/cbc/cbc_done.o
#flag @VMODROOT/libtomcrypt/src/modes/cbc/cbc_encrypt.o
#flag @VMODROOT/libtomcrypt/src/modes/cbc/cbc_getiv.o 
#flag @VMODROOT/libtomcrypt/src/modes/cbc/cbc_setiv.o
#flag @VMODROOT/libtomcrypt/src/modes/cbc/cbc_start.o
#flag @VMODROOT/libtomcrypt/src/modes/cfb/cfb_decrypt.o 
#flag @VMODROOT/libtomcrypt/src/modes/cfb/cfb_done.o
#flag @VMODROOT/libtomcrypt/src/modes/cfb/cfb_encrypt.o
#flag @VMODROOT/libtomcrypt/src/modes/cfb/cfb_getiv.o 
#flag @VMODROOT/libtomcrypt/src/modes/cfb/cfb_setiv.o
#flag @VMODROOT/libtomcrypt/src/modes/cfb/cfb_start.o
#flag @VMODROOT/libtomcrypt/src/modes/ctr/ctr_decrypt.o 
#flag @VMODROOT/libtomcrypt/src/modes/ctr/ctr_done.o
#flag @VMODROOT/libtomcrypt/src/modes/ctr/ctr_encrypt.o
#flag @VMODROOT/libtomcrypt/src/modes/ctr/ctr_getiv.o 
#flag @VMODROOT/libtomcrypt/src/modes/ctr/ctr_setiv.o
#flag @VMODROOT/libtomcrypt/src/modes/ctr/ctr_start.o
#flag @VMODROOT/libtomcrypt/src/modes/ctr/ctr_test.o 
#flag @VMODROOT/libtomcrypt/src/modes/ecb/ecb_decrypt.o
#flag @VMODROOT/libtomcrypt/src/modes/ecb/ecb_done.o
#flag @VMODROOT/libtomcrypt/src/modes/ecb/ecb_encrypt.o 
#flag @VMODROOT/libtomcrypt/src/modes/ecb/ecb_start.o
#flag @VMODROOT/libtomcrypt/src/modes/f8/f8_decrypt.o
#flag @VMODROOT/libtomcrypt/src/modes/f8/f8_done.o
#flag @VMODROOT/libtomcrypt/src/modes/f8/f8_encrypt.o 
#flag @VMODROOT/libtomcrypt/src/modes/f8/f8_getiv.o
#flag @VMODROOT/libtomcrypt/src/modes/f8/f8_setiv.o
#flag @VMODROOT/libtomcrypt/src/modes/f8/f8_start.o
#flag @VMODROOT/libtomcrypt/src/modes/f8/f8_test_mode.o 
#flag @VMODROOT/libtomcrypt/src/modes/lrw/lrw_decrypt.o
#flag @VMODROOT/libtomcrypt/src/modes/lrw/lrw_done.o
#flag @VMODROOT/libtomcrypt/src/modes/lrw/lrw_encrypt.o 
#flag @VMODROOT/libtomcrypt/src/modes/lrw/lrw_getiv.o
#flag @VMODROOT/libtomcrypt/src/modes/lrw/lrw_process.o
#flag @VMODROOT/libtomcrypt/src/modes/lrw/lrw_setiv.o 
#flag @VMODROOT/libtomcrypt/src/modes/lrw/lrw_start.o
#flag @VMODROOT/libtomcrypt/src/modes/lrw/lrw_test.o
#flag @VMODROOT/libtomcrypt/src/modes/ofb/ofb_decrypt.o
#flag @VMODROOT/libtomcrypt/src/modes/ofb/ofb_done.o 
#flag @VMODROOT/libtomcrypt/src/modes/ofb/ofb_encrypt.o
#flag @VMODROOT/libtomcrypt/src/modes/ofb/ofb_getiv.o
#flag @VMODROOT/libtomcrypt/src/modes/ofb/ofb_setiv.o 
#flag @VMODROOT/libtomcrypt/src/modes/ofb/ofb_start.o
#flag @VMODROOT/libtomcrypt/src/modes/xts/xts_decrypt.o
#flag @VMODROOT/libtomcrypt/src/modes/xts/xts_done.o 
#flag @VMODROOT/libtomcrypt/src/modes/xts/xts_encrypt.o
#flag @VMODROOT/libtomcrypt/src/modes/xts/xts_init.o
#flag @VMODROOT/libtomcrypt/src/modes/xts/xts_mult_x.o 
#flag @VMODROOT/libtomcrypt/src/modes/xts/xts_test.o
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/bit/der_decode_bit_string.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/bit/der_decode_raw_bit_string.o
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/bit/der_encode_bit_string.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/bit/der_encode_raw_bit_string.o
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/bit/der_length_bit_string.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/boolean/der_decode_boolean.o
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/boolean/der_encode_boolean.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/boolean/der_length_boolean.o
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/choice/der_decode_choice.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/generalizedtime/der_decode_generalizedtime.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/generalizedtime/der_encode_generalizedtime.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/generalizedtime/der_length_generalizedtime.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/ia5/der_decode_ia5_string.o
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/ia5/der_encode_ia5_string.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/ia5/der_length_ia5_string.o
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/integer/der_decode_integer.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/integer/der_encode_integer.o
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/integer/der_length_integer.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/object_identifier/der_decode_object_identifier.o
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/object_identifier/der_encode_object_identifier.o
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/object_identifier/der_length_object_identifier.o
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/octet/der_decode_octet_string.o
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/octet/der_encode_octet_string.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/octet/der_length_octet_string.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/printable_string/der_decode_printable_string.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/printable_string/der_encode_printable_string.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/printable_string/der_length_printable_string.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/sequence/der_decode_sequence_ex.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/sequence/der_decode_sequence_flexi.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/sequence/der_decode_sequence_multi.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/sequence/der_decode_subject_public_key_info.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/sequence/der_encode_sequence_ex.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/sequence/der_encode_sequence_multi.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/sequence/der_encode_subject_public_key_info.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/sequence/der_length_sequence.o
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/sequence/der_sequence_free.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/sequence/der_sequence_shrink.o
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/set/der_encode_set.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/set/der_encode_setof.o
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/short_integer/der_decode_short_integer.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/short_integer/der_encode_short_integer.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/short_integer/der_length_short_integer.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/teletex_string/der_decode_teletex_string.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/teletex_string/der_length_teletex_string.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/utctime/der_decode_utctime.o
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/utctime/der_encode_utctime.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/utctime/der_length_utctime.o
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/utf8/der_decode_utf8_string.o 
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/utf8/der_encode_utf8_string.o
#flag @VMODROOT/libtomcrypt/src/pk/asn1/der/utf8/der_length_utf8_string.o 
#flag @VMODROOT/libtomcrypt/src/pk/dh/dh.o
#flag @VMODROOT/libtomcrypt/src/pk/dh/dh_check_pubkey.o
#flag @VMODROOT/libtomcrypt/src/pk/dh/dh_export.o
#flag @VMODROOT/libtomcrypt/src/pk/dh/dh_export_key.o 
#flag @VMODROOT/libtomcrypt/src/pk/dh/dh_free.o
#flag @VMODROOT/libtomcrypt/src/pk/dh/dh_generate_key.o
#flag @VMODROOT/libtomcrypt/src/pk/dh/dh_import.o
#flag @VMODROOT/libtomcrypt/src/pk/dh/dh_set.o 
#flag @VMODROOT/libtomcrypt/src/pk/dh/dh_set_pg_dhparam.o
#flag @VMODROOT/libtomcrypt/src/pk/dh/dh_shared_secret.o
#flag @VMODROOT/libtomcrypt/src/pk/dsa/dsa_decrypt_key.o 
#flag @VMODROOT/libtomcrypt/src/pk/dsa/dsa_encrypt_key.o
#flag @VMODROOT/libtomcrypt/src/pk/dsa/dsa_export.o
#flag @VMODROOT/libtomcrypt/src/pk/dsa/dsa_free.o 
#flag @VMODROOT/libtomcrypt/src/pk/dsa/dsa_generate_key.o
#flag @VMODROOT/libtomcrypt/src/pk/dsa/dsa_generate_pqg.o
#flag @VMODROOT/libtomcrypt/src/pk/dsa/dsa_import.o 
#flag @VMODROOT/libtomcrypt/src/pk/dsa/dsa_make_key.o
#flag @VMODROOT/libtomcrypt/src/pk/dsa/dsa_set.o
#flag @VMODROOT/libtomcrypt/src/pk/dsa/dsa_set_pqg_dsaparam.o 
#flag @VMODROOT/libtomcrypt/src/pk/dsa/dsa_shared_secret.o
#flag @VMODROOT/libtomcrypt/src/pk/dsa/dsa_sign_hash.o
#flag @VMODROOT/libtomcrypt/src/pk/dsa/dsa_verify_hash.o 
#flag @VMODROOT/libtomcrypt/src/pk/dsa/dsa_verify_key.o
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ecc.o
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ecc_ansi_x963_export.o 
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ecc_ansi_x963_import.o
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ecc_decrypt_key.o
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ecc_encrypt_key.o 
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ecc_export.o
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ecc_free.o
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ecc_get_size.o
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ecc_import.o 
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ecc_make_key.o
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ecc_shared_secret.o
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ecc_sign_hash.o 
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ecc_sizes.o
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ecc_test.o
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ecc_verify_hash.o 
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ltc_ecc_is_valid_idx.o
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ltc_ecc_map.o
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ltc_ecc_mul2add.o 
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ltc_ecc_mulmod.o
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ltc_ecc_mulmod_timing.o
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ltc_ecc_points.o 
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ltc_ecc_projective_add_point.o
#flag @VMODROOT/libtomcrypt/src/pk/ecc/ltc_ecc_projective_dbl_point.o 
#flag @VMODROOT/libtomcrypt/src/pk/katja/katja_decrypt_key.o
#flag @VMODROOT/libtomcrypt/src/pk/katja/katja_encrypt_key.o
#flag @VMODROOT/libtomcrypt/src/pk/katja/katja_export.o 
#flag @VMODROOT/libtomcrypt/src/pk/katja/katja_exptmod.o
#flag @VMODROOT/libtomcrypt/src/pk/katja/katja_free.o
#flag @VMODROOT/libtomcrypt/src/pk/katja/katja_import.o 
#flag @VMODROOT/libtomcrypt/src/pk/katja/katja_make_key.o
#flag @VMODROOT/libtomcrypt/src/pk/pkcs1/pkcs_1_i2osp.o
#flag @VMODROOT/libtomcrypt/src/pk/pkcs1/pkcs_1_mgf1.o 
#flag @VMODROOT/libtomcrypt/src/pk/pkcs1/pkcs_1_oaep_decode.o
#flag @VMODROOT/libtomcrypt/src/pk/pkcs1/pkcs_1_oaep_encode.o
#flag @VMODROOT/libtomcrypt/src/pk/pkcs1/pkcs_1_os2ip.o 
#flag @VMODROOT/libtomcrypt/src/pk/pkcs1/pkcs_1_pss_decode.o
#flag @VMODROOT/libtomcrypt/src/pk/pkcs1/pkcs_1_pss_encode.o
#flag @VMODROOT/libtomcrypt/src/pk/pkcs1/pkcs_1_v1_5_decode.o 
#flag @VMODROOT/libtomcrypt/src/pk/pkcs1/pkcs_1_v1_5_encode.o
#flag @VMODROOT/libtomcrypt/src/pk/rsa/rsa_decrypt_key.o
#flag @VMODROOT/libtomcrypt/src/pk/rsa/rsa_encrypt_key.o 
#flag @VMODROOT/libtomcrypt/src/pk/rsa/rsa_export.o
#flag @VMODROOT/libtomcrypt/src/pk/rsa/rsa_exptmod.o
#flag @VMODROOT/libtomcrypt/src/pk/rsa/rsa_free.o
#flag @VMODROOT/libtomcrypt/src/pk/rsa/rsa_get_size.o 
#flag @VMODROOT/libtomcrypt/src/pk/rsa/rsa_import.o
#flag @VMODROOT/libtomcrypt/src/pk/rsa/rsa_import_pkcs8.o
#flag @VMODROOT/libtomcrypt/src/pk/rsa/rsa_import_x509.o 
#flag @VMODROOT/libtomcrypt/src/pk/rsa/rsa_make_key.o
#flag @VMODROOT/libtomcrypt/src/pk/rsa/rsa_set.o
#flag @VMODROOT/libtomcrypt/src/pk/rsa/rsa_sign_hash.o 
#flag @VMODROOT/libtomcrypt/src/pk/rsa/rsa_sign_saltlen_get.o
#flag @VMODROOT/libtomcrypt/src/pk/rsa/rsa_verify_hash.o
#flag @VMODROOT/libtomcrypt/src/prngs/chacha20.o
#flag @VMODROOT/libtomcrypt/src/prngs/fortuna.o 
#flag @VMODROOT/libtomcrypt/src/prngs/rc4.o
#flag @VMODROOT/libtomcrypt/src/prngs/rng_get_bytes.o
#flag @VMODROOT/libtomcrypt/src/prngs/rng_make_prng.o
#flag @VMODROOT/libtomcrypt/src/prngs/sober128.o 
#flag @VMODROOT/libtomcrypt/src/prngs/sprng.o
#flag @VMODROOT/libtomcrypt/src/prngs/yarrow.o
#flag @VMODROOT/libtomcrypt/src/stream/chacha/chacha_crypt.o
#flag @VMODROOT/libtomcrypt/src/stream/chacha/chacha_done.o 
#flag @VMODROOT/libtomcrypt/src/stream/chacha/chacha_ivctr32.o
#flag @VMODROOT/libtomcrypt/src/stream/chacha/chacha_ivctr64.o 
#flag @VMODROOT/libtomcrypt/src/stream/chacha/chacha_keystream.o
#flag @VMODROOT/libtomcrypt/src/stream/chacha/chacha_setup.o
#flag @VMODROOT/libtomcrypt/src/stream/chacha/chacha_test.o 
#flag @VMODROOT/libtomcrypt/src/stream/rc4/rc4_stream.o
#flag @VMODROOT/libtomcrypt/src/stream/rc4/rc4_test.o
#flag @VMODROOT/libtomcrypt/src/stream/sober128/sober128_stream.o 
#flag @VMODROOT/libtomcrypt/src/stream/sober128/sober128_test.o

#include "@VMODROOT/tc_helper.h"