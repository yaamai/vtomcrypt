#ifdef byte
#undef byte
#endif

// These arent defined
// normally in C that would be fine but since V 
// makes sure that all referenced C funcitons actually exist
// we need to put them here
int s_read_arc4random(void *p, size_t n) {}
int s_read_getrandom(void *p, size_t n) {}
int s_read_urandom(void *p, size_t n) {}
int s_read_ltm_rng(void *p, size_t n) {}


// v can't compile a C struct containing with no tag defined.
// eg.) typedef struct {} AAA; fails, typedef struct AAA {}; ok.
/** An ECC key */
typedef struct Ecc_key {
    /** Type of key, PK_PRIVATE or PK_PUBLIC */
    int type;

    /** Index into the ltc_ecc_sets[] for the parameters of this curve; if -1, then this key is using user supplied curve in dp */
    int idx;

    /** pointer to domain parameters; either points to NIST curves (identified by idx >= 0) or user supplied curve */
    const ltc_ecc_set_type *dp;

    /** The public key */
    ecc_point pubkey;

    /** The private key */
    void *k;
};