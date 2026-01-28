/*
 * Decompiled with CFR 0.152.
 */
package com.keyfactor.util.crypto.algorithm;

import java.util.Arrays;
import java.util.List;

public final class AlgorithmConstants {
    public static final String SIGALG_MD5_WITH_RSA = "MD5WithRSA";
    public static final String SIGALG_SHA1_WITH_RSA = "SHA1WithRSA";
    public static final String SIGALG_SHA256_WITH_RSA = "SHA256WithRSA";
    public static final String SIGALG_SHA384_WITH_RSA = "SHA384WithRSA";
    public static final String SIGALG_SHA512_WITH_RSA = "SHA512WithRSA";
    public static final String SIGALG_SHA3_256_WITH_RSA = "SHA3-256withRSA";
    public static final String SIGALG_SHA3_384_WITH_RSA = "SHA3-384withRSA";
    public static final String SIGALG_SHA3_512_WITH_RSA = "SHA3-512withRSA";
    public static final String SIGALG_SHA1_WITH_ECDSA = "SHA1withECDSA";
    public static final String SIGALG_SHA224_WITH_ECDSA = "SHA224withECDSA";
    public static final String SIGALG_SHA256_WITH_ECDSA = "SHA256withECDSA";
    public static final String SIGALG_SHA384_WITH_ECDSA = "SHA384withECDSA";
    public static final String SIGALG_SHA512_WITH_ECDSA = "SHA512withECDSA";
    public static final String SIGALG_SHA3_256_WITH_ECDSA = "SHA3-256withECDSA";
    public static final String SIGALG_SHA3_384_WITH_ECDSA = "SHA3-384withECDSA";
    public static final String SIGALG_SHA3_512_WITH_ECDSA = "SHA3-512withECDSA";
    public static final String SIGALG_SHA256_WITH_RSA_AND_MGF1 = "SHA256withRSAandMGF1";
    public static final String SIGALG_SHA384_WITH_RSA_AND_MGF1 = "SHA384withRSAandMGF1";
    public static final String SIGALG_SHA512_WITH_RSA_AND_MGF1 = "SHA512withRSAandMGF1";
    public static final String SIGALG_SHA1_WITH_RSA_AND_MGF1 = "SHA1withRSAandMGF1";
    public static final String SIGALG_ED25519 = "Ed25519";
    public static final String SIGALG_ED448 = "Ed448";
    public static final String SIGALG_FALCON512 = "FALCON-512";
    public static final String SIGALG_FALCON1024 = "FALCON-1024";
    public static final String SIGALG_MLKEM512 = "ML-KEM-512";
    public static final String SIGALG_MLKEM768 = "ML-KEM-768";
    public static final String SIGALG_MLKEM1024 = "ML-KEM-1024";
    public static final String SIGALG_MLDSA44 = "ML-DSA-44";
    public static final String SIGALG_MLDSA65 = "ML-DSA-65";
    public static final String SIGALG_MLDSA87 = "ML-DSA-87";
    public static final String SIGALG_LMS = "LMS";
    public static final String SIGALG_SLHDSA_SHA2_128S = "SLH-DSA-SHA2-128S";
    public static final String SIGALG_SLHDSA_SHAKE_128S = "SLH-DSA-SHAKE-128S";
    public static final String SIGALG_SLHDSA_SHA2_128F = "SLH-DSA-SHA2-128F";
    public static final String SIGALG_SLHDSA_SHAKE_128F = "SLH-DSA-SHAKE-128F";
    public static final String SIGALG_SLHDSA_SHA2_192S = "SLH-DSA-SHA2-192S";
    public static final String SIGALG_SLHDSA_SHAKE_192S = "SLH-DSA-SHAKE-192S";
    public static final String SIGALG_SLHDSA_SHA2_192F = "SLH-DSA-SHA2-192F";
    public static final String SIGALG_SLHDSA_SHAKE_192F = "SLH-DSA-SHAKE-192F";
    public static final String SIGALG_SLHDSA_SHA2_256S = "SLH-DSA-SHA2-256S";
    public static final String SIGALG_SLHDSA_SHAKE_256S = "SLH-DSA-SHAKE-256S";
    public static final String SIGALG_SLHDSA_SHA2_256F = "SLH-DSA-SHA2-256F";
    public static final String SIGALG_SLHDSA_SHAKE_256F = "SLH-DSA-SHAKE-256F";
    public static final String[] AVAILABLE_SIGALGS = new String[]{"SHA1WithRSA", "SHA256WithRSA", "SHA384WithRSA", "SHA512WithRSA", "SHA3-256withRSA", "SHA3-384withRSA", "SHA3-512withRSA", "SHA256withRSAandMGF1", "SHA384withRSAandMGF1", "SHA512withRSAandMGF1", "SHA1withECDSA", "SHA224withECDSA", "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA", "SHA3-256withECDSA", "SHA3-384withECDSA", "SHA3-512withECDSA", "Ed25519", "Ed448", "FALCON-512", "FALCON-1024", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "LMS", "SLH-DSA-SHA2-128S", "SLH-DSA-SHAKE-128S", "SLH-DSA-SHA2-128F", "SLH-DSA-SHAKE-128F", "SLH-DSA-SHA2-192S", "SLH-DSA-SHAKE-192S", "SLH-DSA-SHA2-192F", "SLH-DSA-SHAKE-192F", "SLH-DSA-SHA2-256S", "SLH-DSA-SHAKE-256S", "SLH-DSA-SHA2-256F", "SLH-DSA-SHAKE-256F"};
    public static final String KEYALGORITHM_RSA = "RSA";
    public static final String KEYALGORITHM_EC = "EC";
    public static final String KEYALGORITHM_ECDSA = "ECDSA";
    public static final String KEYALGORITHM_ED25519 = "Ed25519";
    public static final String KEYALGORITHM_ED448 = "Ed448";
    public static final String KEYALGORITHM_FALCON512 = "FALCON-512";
    public static final String KEYALGORITHM_FALCON1024 = "FALCON-1024";
    public static final String KEYALGORITHM_MLKEM512 = "ML-KEM-512";
    public static final String KEYALGORITHM_MLKEM768 = "ML-KEM-768";
    public static final String KEYALGORITHM_MLKEM1024 = "ML-KEM-1024";
    public static final String KEYALGORITHM_MLDSA = "ML-DSA";
    public static final String KEYALGORITHM_MLDSA44 = "ML-DSA-44";
    public static final String KEYALGORITHM_MLDSA65 = "ML-DSA-65";
    public static final String KEYALGORITHM_MLDSA87 = "ML-DSA-87";
    public static final String KEYALGORITHM_SLHDSA_SHA2_128S = "SLH-DSA-SHA2-128S";
    public static final String KEYALGORITHM_SLHDSA_SHAKE_128S = "SLH-DSA-SHAKE-128S";
    public static final String KEYALGORITHM_SLHDSA_SHA2_128F = "SLH-DSA-SHA2-128F";
    public static final String KEYALGORITHM_SLHDSA_SHAKE_128F = "SLH-DSA-SHAKE-128F";
    public static final String KEYALGORITHM_SLHDSA_SHA2_192S = "SLH-DSA-SHA2-192S";
    public static final String KEYALGORITHM_SLHDSA_SHAKE_192S = "SLH-DSA-SHAKE-192S";
    public static final String KEYALGORITHM_SLHDSA_SHA2_192F = "SLH-DSA-SHA2-192F";
    public static final String KEYALGORITHM_SLHDSA_SHAKE_192F = "SLH-DSA-SHAKE-192F";
    public static final String KEYALGORITHM_SLHDSA_SHA2_256S = "SLH-DSA-SHA2-256S";
    public static final String KEYALGORITHM_SLHDSA_SHAKE_256S = "SLH-DSA-SHAKE-256S";
    public static final String KEYALGORITHM_SLHDSA_SHA2_256F = "SLH-DSA-SHA2-256F";
    public static final String KEYALGORITHM_SLHDSA_SHAKE_256F = "SLH-DSA-SHAKE-256F";
    public static final String KEYALGORITHM_LMS = "LMS";
    public static final String KEYALGORITHM_HSS = "HSS";
    public static final String HASHALGORITHM_SHA1 = "SHA1";
    public static final String HASHALGORITHM_SHA224 = "SHA224";
    public static final String HASHALGORITHM_SHA256 = "SHA256";
    public static final String HASHALGORITHM_SHA384 = "SHA384";
    public static final String HASHALGORITHM_SHA512 = "SHA512";
    public static final String HASHALGORITHM_SHA3_256 = "SHA3-256";
    public static final String HASHALGORITHM_SHA3_384 = "SHA3-384";
    public static final String HASHALGORITHM_SHA3_512 = "SHA3-512";
    public static final List<String> ECCDH_PERMITTED_CURVES = Arrays.asList("secp224r1", "P-224", "prime256v1", "secp256r1", "P-256", "prime384v1", "secp384r1", "P-384", "prime521v1", "secp521r1", "P-521", "sect233k1", "K-233", "sect283k1", "K-283", "sect409k1", "K-409", "sect571k1", "K-571", "sect233r1", "B-233", "sect283r1", "B-283", "sect309r1", "B-409", "sect571r1", "B-571");
    public static final List<String> BLACKLISTED_EC_CURVES = Arrays.asList(new String[0]);
    public static final List<String> EXTRA_EC_CURVES = Arrays.asList(new String[0]);

    private AlgorithmConstants() {
    }
}

