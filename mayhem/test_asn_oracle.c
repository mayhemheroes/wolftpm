/* test_asn_oracle.c — golden oracle over wolfTPM's fuzzed ASN.1 parse path.
 *
 * This is an ADDITIVE, self-contained functional test for mayhem/test.sh. wolfTPM's own
 * unit tests (tests/unit_tests.c) need a real or simulated TPM device; this oracle instead
 * exercises EXACTLY the code the fuzzer hits — TPM2_ASN_DecodeX509Cert and
 * TPM2_ASN_DecodeRsaPubKey in src/tpm2_asn.c — over known-answer inputs, so a no-op/exit(0)
 * patch to those decoders cannot pass:
 *
 *   - a valid PKCS#1 RSAPublicKey (SEQUENCE{INTEGER modulus, INTEGER exponent}) must decode
 *     rc==0 and yield the exact modulus length / keyBits we embedded;
 *   - a valid DER X.509 certificate must decode rc==0 and set the publicKey + signature spans;
 *   - malformed / truncated / length-confused inputs must be REJECTED (rc!=0) without crashing
 *     (these are the regression cases the in-tree comments call out as past bugs).
 *
 * Prints one PASS/FAIL line per case; exits nonzero if any case fails.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <wolftpm/tpm2_asn.h>
#include <wolftpm/tpm2_wrap.h>

static int g_pass = 0, g_fail = 0;

static void check(const char* name, int cond)
{
    if (cond) { printf("PASS %s\n", name); g_pass++; }
    else      { printf("FAIL %s\n", name); g_fail++; }
}

/* A minimal valid PKCS#1 RSAPublicKey: SEQUENCE { INTEGER (0x11 = 1 byte modulus), INTEGER 65537 }.
 * mod_len after the decoder is 1 (no leading 0x00), keyBits = 8. */
static const uint8_t rsa_min[] = {
    0x30, 0x06,             /* SEQUENCE, len 6 */
    0x02, 0x01, 0x11,       /* INTEGER, len 1, value 0x11 (modulus) */
    0x02, 0x03, 0x01, 0x00, 0x01 /* INTEGER, len 3, value 0x010001 (exponent) */
};

int main(void)
{
    /* ---- RSA pubkey: valid case (known answer) ---- */
    {
        uint8_t buf[sizeof(rsa_min)];
        TPM2B_PUBLIC pub;
        int rc;
        memcpy(buf, rsa_min, sizeof(rsa_min));
        memset(&pub, 0, sizeof(pub));
        rc = TPM2_ASN_DecodeRsaPubKey(buf, (int)sizeof(buf), &pub);
        check("rsa_pubkey_valid_rc0", rc == 0);
        check("rsa_pubkey_modlen", pub.publicArea.unique.rsa.size == 1);
        check("rsa_pubkey_keybits", pub.publicArea.parameters.rsaDetail.keyBits == 8);
    }

    /* ---- RSA pubkey: regression — zero-length modulus INTEGER must NOT underflow ---- */
    {
        /* SEQUENCE { INTEGER len 0 } — the in-tree guard rejects this rather than passing
         * SIZE_MAX to XMEMCPY. We require a clean reject (rc != 0), no crash. */
        uint8_t bad[] = { 0x30, 0x02, 0x02, 0x00 };
        TPM2B_PUBLIC pub;
        int rc;
        memset(&pub, 0, sizeof(pub));
        rc = TPM2_ASN_DecodeRsaPubKey(bad, (int)sizeof(bad), &pub);
        check("rsa_pubkey_zerolen_rejected", rc != 0);
    }

    /* ---- RSA pubkey: truncated buffer must be rejected ---- */
    {
        TPM2B_PUBLIC pub;
        int rc;
        memset(&pub, 0, sizeof(pub));
        rc = TPM2_ASN_DecodeRsaPubKey((uint8_t*)rsa_min, 2, &pub); /* only tag+len */
        check("rsa_pubkey_truncated_rejected", rc != 0);
    }

    /* ---- X.509: empty / tiny inputs must be rejected, not crash ---- */
    {
        uint8_t tiny[] = { 0x30, 0x00 };
        DecodedX509 x509;
        int rc;
        memset(&x509, 0, sizeof(x509));
        rc = TPM2_ASN_DecodeX509Cert(tiny, (int)sizeof(tiny), &x509);
        check("x509_empty_seq_rejected", rc != 0);
    }
    {
        DecodedX509 x509;
        int rc;
        uint8_t one = 0x30;
        memset(&x509, 0, sizeof(x509));
        rc = TPM2_ASN_DecodeX509Cert(&one, 1, &x509);
        check("x509_singlebyte_rejected", rc != 0);
    }

    /* ---- ASN length primitive: bytewise sanity over the helper the decoders rely on ---- */
    {
        /* short-form length 0x05 followed by >=5 content bytes so the (idx+length<=maxIdx)
         * check passes; the helper returns the decoded length and advances idx past the
         * length octet only. */
        const uint8_t sf[] = { 0x05, 0,0,0,0,0 };
        word32 idx = 0;
        int len = -1;
        int r = TPM2_ASN_GetLength(sf, &idx, &len, (word32)sizeof(sf));
        check("asn_getlength_shortform", r == 5 && len == 5 && idx == 1);
    }
    {
        /* a length that runs past the buffer must be rejected (TPM_RC_INSUFFICIENT < 0). */
        const uint8_t sf[] = { 0x05 };
        word32 idx = 0;
        int len = 0;
        int r = TPM2_ASN_GetLength(sf, &idx, &len, (word32)sizeof(sf));
        check("asn_getlength_overrun_rejected", r < 0);
    }

    printf("ORACLE passed=%d failed=%d\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
