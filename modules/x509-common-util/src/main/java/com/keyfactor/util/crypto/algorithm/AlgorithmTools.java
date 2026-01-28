/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.commons.lang.StringUtils
 *  org.apache.log4j.Logger
 *  org.bouncycastle.asn1.ASN1ObjectIdentifier
 *  org.bouncycastle.asn1.ASN1Primitive
 *  org.bouncycastle.asn1.anssi.ANSSINamedCurves
 *  org.bouncycastle.asn1.bc.BCObjectIdentifiers
 *  org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves
 *  org.bouncycastle.asn1.edec.EdECObjectIdentifiers
 *  org.bouncycastle.asn1.gm.GMNamedCurves
 *  org.bouncycastle.asn1.nist.NISTNamedCurves
 *  org.bouncycastle.asn1.nist.NISTObjectIdentifiers
 *  org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
 *  org.bouncycastle.asn1.pkcs.RSASSAPSSparams
 *  org.bouncycastle.asn1.sec.SECNamedCurves
 *  org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves
 *  org.bouncycastle.asn1.x509.AlgorithmIdentifier
 *  org.bouncycastle.asn1.x9.ECNamedCurveTable
 *  org.bouncycastle.asn1.x9.X962NamedCurves
 *  org.bouncycastle.asn1.x9.X9ECParameters
 *  org.bouncycastle.asn1.x9.X9ObjectIdentifiers
 *  org.bouncycastle.cms.CMSSignedGenerator
 *  org.bouncycastle.jcajce.interfaces.MLDSAKey
 *  org.bouncycastle.jcajce.interfaces.MLDSAPublicKey
 *  org.bouncycastle.jcajce.interfaces.MLKEMKey
 *  org.bouncycastle.jcajce.interfaces.MLKEMPublicKey
 *  org.bouncycastle.jcajce.interfaces.SLHDSAKey
 *  org.bouncycastle.jcajce.interfaces.SLHDSAPublicKey
 *  org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey
 *  org.bouncycastle.jcajce.spec.MLDSAParameterSpec
 *  org.bouncycastle.jcajce.spec.MLKEMParameterSpec
 *  org.bouncycastle.jcajce.spec.SLHDSAParameterSpec
 *  org.bouncycastle.jce.ECGOST3410NamedCurveTable
 *  org.bouncycastle.jce.ECNamedCurveTable
 *  org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
 *  org.bouncycastle.jce.spec.ECNamedCurveSpec
 *  org.bouncycastle.jce.spec.ECParameterSpec
 *  org.bouncycastle.math.ec.ECCurve
 *  org.bouncycastle.math.ec.ECPoint
 *  org.bouncycastle.operator.DefaultAlgorithmNameFinder
 *  org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
 *  org.bouncycastle.pqc.jcajce.interfaces.FalconKey
 *  org.bouncycastle.pqc.jcajce.interfaces.FalconPublicKey
 *  org.bouncycastle.pqc.jcajce.interfaces.LMSKey
 *  org.bouncycastle.pqc.jcajce.provider.lms.BCLMSPublicKey
 *  org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec
 */
package com.keyfactor.util.crypto.algorithm;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.SignatureParameter;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.anssi.ANSSINamedCurves;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.jcajce.interfaces.MLDSAKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.interfaces.MLKEMKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPublicKey;
import org.bouncycastle.jcajce.interfaces.SLHDSAKey;
import org.bouncycastle.jcajce.interfaces.SLHDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.pqc.jcajce.interfaces.FalconKey;
import org.bouncycastle.pqc.jcajce.interfaces.FalconPublicKey;
import org.bouncycastle.pqc.jcajce.interfaces.LMSKey;
import org.bouncycastle.pqc.jcajce.provider.lms.BCLMSPublicKey;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

public abstract class AlgorithmTools {
    public static final Logger log = Logger.getLogger(AlgorithmTools.class);
    public static final String KEYSPEC_UNKNOWN = "unknown";
    private static final List<String> SIG_ALGS_RSA_NOSHA1_INTERNAL = Arrays.asList("SHA256WithRSA", "SHA256withRSAandMGF1", "SHA384withRSAandMGF1", "SHA512withRSAandMGF1", "SHA384WithRSA", "SHA512WithRSA", "SHA3-256withRSA", "SHA3-384withRSA", "SHA3-512withRSA");
    public static final List<String> SIG_ALGS_RSA_NOSHA1 = Collections.unmodifiableList(SIG_ALGS_RSA_NOSHA1_INTERNAL);
    private static final List<String> SIG_ALGS_RSA_SHA1_INTERNAL = Arrays.asList("SHA1WithRSA", "SHA1withRSAandMGF1");
    public static final List<String> SIG_ALGS_RSA = Collections.unmodifiableList(AlgorithmTools.union(SIG_ALGS_RSA_SHA1_INTERNAL, SIG_ALGS_RSA_NOSHA1_INTERNAL));
    public static final List<String> SIG_ALGS_ECDSA = Collections.unmodifiableList(Arrays.asList("SHA1withECDSA", "SHA224withECDSA", "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA", "SHA3-256withECDSA", "SHA3-384withECDSA", "SHA3-512withECDSA"));
    public static final List<Integer> DEFAULTBITLENGTHS_RSA = Arrays.asList(1024, 1536, 2048, 3072, 4096, 6144, 8192);
    public static final List<Integer> DEFAULTBITLENGTHS_EC = AlgorithmTools.getAllNamedEcCurveBitLengths();
    public static final List<String> SIG_ALGS_ED25519 = Collections.unmodifiableList(Arrays.asList("Ed25519"));
    public static final List<String> SIG_ALGS_ED448 = Collections.unmodifiableList(Arrays.asList("Ed448"));
    public static final List<String> SIG_ALGS_FALCON512 = Collections.unmodifiableList(Arrays.asList("FALCON-512"));
    public static final List<String> SIG_ALGS_FALCON1024 = Collections.unmodifiableList(Arrays.asList("FALCON-1024"));
    public static final List<String> SIG_ALGS_MLKEM512 = Collections.unmodifiableList(Arrays.asList("ML-KEM-512"));
    public static final List<String> SIG_ALGS_MLKEM768 = Collections.unmodifiableList(Arrays.asList("ML-KEM-768"));
    public static final List<String> SIG_ALGS_MLKEM1024 = Collections.unmodifiableList(Arrays.asList("ML-KEM-1024"));
    public static final List<String> SIG_ALGS_MLDSA44 = Collections.unmodifiableList(Arrays.asList("ML-DSA-44"));
    public static final List<String> SIG_ALGS_MLDSA65 = Collections.unmodifiableList(Arrays.asList("ML-DSA-65"));
    public static final List<String> SIG_ALGS_MLDSA87 = Collections.unmodifiableList(Arrays.asList("ML-DSA-87"));
    public static final List<String> SIG_ALGS_LMS = Collections.unmodifiableList(Arrays.asList("LMS"));
    public static final List<String> SIG_ALGS_SLHDSA_SHA2_128S = Collections.unmodifiableList(Arrays.asList("SLH-DSA-SHA2-128S"));
    public static final List<String> SIG_ALGS_SLHDSA_SHAKE_128S = Collections.unmodifiableList(Arrays.asList("SLH-DSA-SHAKE-128S"));
    public static final List<String> SIG_ALGS_SLHDSA_SHA2_128F = Collections.unmodifiableList(Arrays.asList("SLH-DSA-SHA2-128F"));
    public static final List<String> SIG_ALGS_SLHDSA_SHAKE_128F = Collections.unmodifiableList(Arrays.asList("SLH-DSA-SHAKE-128F"));
    public static final List<String> SIG_ALGS_SLHDSA_SHA2_192S = Collections.unmodifiableList(Arrays.asList("SLH-DSA-SHA2-192S"));
    public static final List<String> SIG_ALGS_SLHDSA_SHAKE_192S = Collections.unmodifiableList(Arrays.asList("SLH-DSA-SHAKE-192S"));
    public static final List<String> SIG_ALGS_SLHDSA_SHA2_192F = Collections.unmodifiableList(Arrays.asList("SLH-DSA-SHA2-192F"));
    public static final List<String> SIG_ALGS_SLHDSA_SHAKE_192F = Collections.unmodifiableList(Arrays.asList("SLH-DSA-SHAKE-192F"));
    public static final List<String> SIG_ALGS_SLHDSA_SHA2_256S = Collections.unmodifiableList(Arrays.asList("SLH-DSA-SHA2-256S"));
    public static final List<String> SIG_ALGS_SLHDSA_SHAKE_256S = Collections.unmodifiableList(Arrays.asList("SLH-DSA-SHAKE-256S"));
    public static final List<String> SIG_ALGS_SLHDSA_SHA2_256F = Collections.unmodifiableList(Arrays.asList("SLH-DSA-SHA2-256F"));
    public static final List<String> SIG_ALGS_SLHDSA_SHAKE_256F = Collections.unmodifiableList(Arrays.asList("SLH-DSA-SHAKE-256F"));
    private static Map<String, List<String>> allEcCurveNames = AlgorithmTools.preProcessCurveNames();
    private static Map<String, List<String>> allGostCurveNames = AlgorithmTools.preProcessGostCurveNames();
    private static Map<String, List<String>> ecKeySpecAliases;
    private static final DefaultSignatureAlgorithmIdentifierFinder finder;
    private static final List<String> pqcSigAlgs;

    private static <T> List<T> union(List<T> list1, List<T> list2) {
        HashSet<T> result = new HashSet<T>();
        result.addAll(list1);
        result.addAll(list2);
        return new ArrayList(result);
    }

    public static List<Integer> getAllBitLengths() {
        TreeSet<Integer> allBitLengths = new TreeSet<Integer>();
        allBitLengths.addAll(DEFAULTBITLENGTHS_RSA);
        allBitLengths.addAll(DEFAULTBITLENGTHS_EC);
        return new ArrayList<Integer>(allBitLengths);
    }

    public static String getKeyAlgorithm(PublicKey publickey) {
        String keyAlg;
        if (publickey == null) {
            return null;
        }
        if (publickey instanceof RSAPublicKey) {
            keyAlg = "RSA";
        } else if (publickey instanceof ECPublicKey) {
            keyAlg = "ECDSA";
        } else if (publickey instanceof BCEdDSAPublicKey) {
            keyAlg = publickey.getAlgorithm();
        } else if (publickey.getClass().getCanonicalName().equals("sun.security.ec.ed.EdDSAPublicKeyImpl")) {
            keyAlg = "Ed25519";
        } else if (publickey instanceof FalconKey) {
            keyAlg = publickey.getAlgorithm();
        } else if (publickey instanceof MLDSAKey) {
            keyAlg = publickey.getAlgorithm();
        } else if (publickey instanceof MLKEMKey) {
            keyAlg = publickey.getAlgorithm();
        } else if (publickey instanceof LMSKey) {
            keyAlg = publickey.getAlgorithm();
        } else if (publickey instanceof SLHDSAKey) {
            keyAlg = publickey.getAlgorithm();
        } else {
            if (log.isDebugEnabled()) {
                log.debug((Object)("Unknown key algorithm: " + publickey.getClass().getName() + ", " + publickey.getAlgorithm()));
            }
            keyAlg = null;
        }
        return keyAlg;
    }

    public static List<String> getAvailableKeyAlgorithms() {
        ArrayList<String> ret = new ArrayList<String>(Arrays.asList("ECDSA", "RSA", "Ed25519", "Ed448", "FALCON-512", "FALCON-1024", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "LMS", "SLH-DSA-SHA2-128S", "SLH-DSA-SHAKE-128S", "SLH-DSA-SHA2-128F", "SLH-DSA-SHAKE-128F", "SLH-DSA-SHA2-192S", "SLH-DSA-SHAKE-192S", "SLH-DSA-SHA2-192F", "SLH-DSA-SHAKE-192F", "SLH-DSA-SHA2-256S", "SLH-DSA-SHAKE-256S", "SLH-DSA-SHA2-256F", "SLH-DSA-SHAKE-256F"));
        return ret;
    }

    public static Map<String, List<String>> getNamedEcCurvesMap() {
        return allEcCurveNames;
    }

    public static Map<String, List<String>> getNamedGostCurvesMap() {
        return allGostCurveNames;
    }

    public static Map<String, List<String>> getOnlyNamedEcCurvesMap() {
        Map<String, List<String>> processedCurveNames = AlgorithmTools.getNamedEcCurvesMap();
        Enumeration gostAlgorithms = ECGOST3410NamedCurves.getNames();
        while (gostAlgorithms.hasMoreElements()) {
            processedCurveNames.remove(gostAlgorithms.nextElement());
        }
        return processedCurveNames;
    }

    public static TreeMap<String, String> getFlatNamedEcCurvesMap() {
        TreeMap<String, String> result = new TreeMap<String, String>();
        Map<String, List<String>> map = AlgorithmTools.getOnlyNamedEcCurvesMap();
        Object[] keys = map.keySet().toArray(new String[map.size()]);
        Arrays.sort(keys);
        for (Object name : keys) {
            result.put((String)name, StringTools.getAsStringWithSeparator(" / ", (Collection)map.get(name)));
        }
        return result;
    }

    public static List<String> getNistCurves() {
        ArrayList<String> list = new ArrayList<String>();
        list.addAll(AlgorithmTools.getEcKeySpecAliases("P-256"));
        list.addAll(AlgorithmTools.getEcKeySpecAliases("P-384"));
        list.addAll(AlgorithmTools.getEcKeySpecAliases("P-521"));
        return list;
    }

    @Deprecated
    public static Map<String, List<String>> getNamedEcCurvesMap(boolean hasToBeKnownByDefaultProvider) {
        return AlgorithmTools.getNamedEcCurvesMap();
    }

    @Deprecated
    public static Map<String, List<String>> getNamedGostCurvesMap(boolean hasToBeKnownByDefaultProvider) {
        return AlgorithmTools.getNamedGostCurvesMap();
    }

    @Deprecated
    public static Map<String, List<String>> getOnlyNamedEcCurvesMap(boolean hasToBeKnownByDefaultProvider) {
        return AlgorithmTools.getOnlyNamedEcCurvesMap();
    }

    @Deprecated
    public static TreeMap<String, String> getFlatNamedEcCurvesMap(boolean hasToBeKnownByDefaultProvider) {
        return AlgorithmTools.getFlatNamedEcCurvesMap();
    }

    private static Map<String, List<String>> preProcessCurveNames() {
        HashMap<String, List<String>> processedCurveNames = new HashMap<String, List<String>>();
        HashSet addedCurves = new HashSet();
        Enumeration ecNamedCurvesStandard = org.bouncycastle.jce.ECNamedCurveTable.getNames();
        while (ecNamedCurvesStandard.hasMoreElements()) {
            String ecNamedCurve = (String)ecNamedCurvesStandard.nextElement();
            ECNamedCurveParameterSpec parameterSpec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec((String)ecNamedCurve);
            if (AlgorithmConstants.BLACKLISTED_EC_CURVES.contains(ecNamedCurve) || addedCurves.contains(parameterSpec)) continue;
            processedCurveNames.put(ecNamedCurve, AlgorithmTools.getEcKeySpecAliases(ecNamedCurve));
        }
        for (String ecNamedCurve : AlgorithmConstants.EXTRA_EC_CURVES) {
            ECNamedCurveParameterSpec parameterSpec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec((String)ecNamedCurve);
            if (AlgorithmConstants.BLACKLISTED_EC_CURVES.contains(ecNamedCurve) || addedCurves.contains(parameterSpec)) continue;
            processedCurveNames.put(ecNamedCurve, AlgorithmTools.getEcKeySpecAliases(ecNamedCurve));
        }
        return processedCurveNames;
    }

    private static Map<String, List<String>> preProcessGostCurveNames() {
        HashMap<String, List<String>> processedCurveNames = new HashMap<String, List<String>>();
        HashSet addedCurves = new HashSet();
        Enumeration gostNamedCurvesStandard = ECGOST3410NamedCurves.getNames();
        while (gostNamedCurvesStandard.hasMoreElements()) {
            String gostNamedCurve = (String)gostNamedCurvesStandard.nextElement();
            ECNamedCurveParameterSpec parameterSpec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec((String)gostNamedCurve);
            if (addedCurves.contains(parameterSpec)) continue;
            processedCurveNames.put(gostNamedCurve, AlgorithmTools.getEcKeySpecAliases(gostNamedCurve));
        }
        return processedCurveNames;
    }

    public static int getNamedEcCurveBitLength(String ecNamedCurve) {
        ECNamedCurveParameterSpec ecNamedCurveParameterSpec = ECGOST3410NamedCurveTable.getParameterSpec((String)ecNamedCurve);
        if (ecNamedCurveParameterSpec != null) {
            return ecNamedCurveParameterSpec.getCurve().getFieldSize();
        }
        ecNamedCurveParameterSpec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec((String)ecNamedCurve);
        if (ecNamedCurveParameterSpec == null) {
            return 0;
        }
        return ecNamedCurveParameterSpec.getN().bitLength();
    }

    public static List<Integer> getAllNamedEcCurveBitLengths() {
        TreeSet<Integer> result = new TreeSet<Integer>();
        Enumeration ecCurveNames = org.bouncycastle.jce.ECNamedCurveTable.getNames();
        result.add(0);
        while (ecCurveNames.hasMoreElements()) {
            String ecNamedCurve = (String)ecCurveNames.nextElement();
            result.add(AlgorithmTools.getNamedEcCurveBitLength(ecNamedCurve));
        }
        return new ArrayList<Integer>(result);
    }

    public static List<String> getSignatureAlgorithms(PublicKey publickey) {
        FalconParameterSpec spec;
        if (publickey instanceof RSAPublicKey) {
            return SIG_ALGS_RSA;
        }
        if (publickey instanceof ECPublicKey) {
            ArrayList<String> ecSigAlgs = new ArrayList<String>(SIG_ALGS_ECDSA);
            switch (AlgorithmTools.getNamedEcCurveBitLength(AlgorithmTools.getKeySpecification(publickey))) {
                case 256: {
                    ecSigAlgs.remove("SHA256withECDSA");
                    ecSigAlgs.add(0, "SHA256withECDSA");
                    break;
                }
                case 384: {
                    ecSigAlgs.remove("SHA384withECDSA");
                    ecSigAlgs.add(0, "SHA384withECDSA");
                    break;
                }
                case 521: {
                    ecSigAlgs.remove("SHA512withECDSA");
                    ecSigAlgs.add(0, "SHA512withECDSA");
                    break;
                }
            }
            if (log.isDebugEnabled()) {
                log.debug((Object)("Returning ecAlgs: " + ecSigAlgs));
            }
            return ecSigAlgs;
        }
        if (publickey instanceof BCEdDSAPublicKey) {
            String algo;
            switch (algo = publickey.getAlgorithm()) {
                case "Ed25519": {
                    return SIG_ALGS_ED25519;
                }
                case "Ed448": {
                    return SIG_ALGS_ED448;
                }
            }
        }
        if (publickey instanceof FalconKey) {
            spec = ((FalconKey)publickey).getParameterSpec();
            if (FalconParameterSpec.falcon_512.equals(spec)) {
                return SIG_ALGS_FALCON512;
            }
            if (FalconParameterSpec.falcon_1024.equals(spec)) {
                return SIG_ALGS_FALCON1024;
            }
        }
        if (publickey instanceof MLKEMKey) {
            spec = ((MLKEMKey)publickey).getParameterSpec();
            if (MLKEMParameterSpec.ml_kem_512.equals(spec)) {
                return SIG_ALGS_MLKEM512;
            }
            if (MLKEMParameterSpec.ml_kem_768.equals(spec)) {
                return SIG_ALGS_MLKEM768;
            }
            if (MLKEMParameterSpec.ml_kem_1024.equals(spec)) {
                return SIG_ALGS_MLKEM1024;
            }
        }
        if (publickey instanceof MLDSAKey) {
            spec = ((MLDSAKey)publickey).getParameterSpec();
            if (MLDSAParameterSpec.ml_dsa_44.equals(spec)) {
                return SIG_ALGS_MLDSA44;
            }
            if (MLDSAParameterSpec.ml_dsa_65.equals(spec)) {
                return SIG_ALGS_MLDSA65;
            }
            if (MLDSAParameterSpec.ml_dsa_87.equals(spec)) {
                return SIG_ALGS_MLDSA87;
            }
        }
        if (publickey instanceof LMSKey) {
            return SIG_ALGS_LMS;
        }
        if (publickey instanceof SLHDSAKey) {
            spec = ((SLHDSAKey)publickey).getParameterSpec();
            if (SLHDSAParameterSpec.slh_dsa_sha2_128s.equals(spec)) {
                return SIG_ALGS_SLHDSA_SHA2_128S;
            }
            if (SLHDSAParameterSpec.slh_dsa_shake_128s.equals(spec)) {
                return SIG_ALGS_SLHDSA_SHAKE_128S;
            }
            if (SLHDSAParameterSpec.slh_dsa_sha2_128f.equals(spec)) {
                return SIG_ALGS_SLHDSA_SHA2_128F;
            }
            if (SLHDSAParameterSpec.slh_dsa_shake_128f.equals(spec)) {
                return SIG_ALGS_SLHDSA_SHAKE_128F;
            }
            if (SLHDSAParameterSpec.slh_dsa_sha2_192s.equals(spec)) {
                return SIG_ALGS_SLHDSA_SHA2_192S;
            }
            if (SLHDSAParameterSpec.slh_dsa_shake_192s.equals(spec)) {
                return SIG_ALGS_SLHDSA_SHAKE_192S;
            }
            if (SLHDSAParameterSpec.slh_dsa_sha2_192f.equals(spec)) {
                return SIG_ALGS_SLHDSA_SHA2_192F;
            }
            if (SLHDSAParameterSpec.slh_dsa_shake_192f.equals(spec)) {
                return SIG_ALGS_SLHDSA_SHAKE_192F;
            }
            if (SLHDSAParameterSpec.slh_dsa_sha2_256s.equals(spec)) {
                return SIG_ALGS_SLHDSA_SHA2_256S;
            }
            if (SLHDSAParameterSpec.slh_dsa_shake_256s.equals(spec)) {
                return SIG_ALGS_SLHDSA_SHAKE_256S;
            }
            if (SLHDSAParameterSpec.slh_dsa_sha2_256f.equals(spec)) {
                return SIG_ALGS_SLHDSA_SHA2_256F;
            }
            if (SLHDSAParameterSpec.slh_dsa_shake_256f.equals(spec)) {
                return SIG_ALGS_SLHDSA_SHAKE_256F;
            }
        }
        return Collections.emptyList();
    }

    public static String getKeyAlgorithmFromSigAlg(String signatureAlgorithm) {
        String ret = signatureAlgorithm.contains("ECDSA") ? "ECDSA" : (signatureAlgorithm.equals("Ed25519") ? "Ed25519" : (signatureAlgorithm.equals("Ed448") ? "Ed448" : (signatureAlgorithm.equals("FALCON-512") ? "FALCON-512" : (signatureAlgorithm.equals("FALCON-1024") ? "FALCON-1024" : (signatureAlgorithm.equals("ML-KEM-512") ? "ML-KEM-512" : (signatureAlgorithm.equals("ML-KEM-768") ? "ML-KEM-768" : (signatureAlgorithm.equals("ML-KEM-1024") ? "ML-KEM-1024" : (signatureAlgorithm.equals("ML-DSA-44") ? "ML-DSA-44" : (signatureAlgorithm.equals("ML-DSA-65") ? "ML-DSA-65" : (signatureAlgorithm.equals("ML-DSA-87") ? "ML-DSA-87" : (signatureAlgorithm.equals("LMS") ? "LMS" : (signatureAlgorithm.equals("SLH-DSA-SHA2-128S") ? "SLH-DSA-SHA2-128S" : (signatureAlgorithm.equals("SLH-DSA-SHAKE-128S") ? "SLH-DSA-SHAKE-128S" : (signatureAlgorithm.equals("SLH-DSA-SHA2-128F") ? "SLH-DSA-SHA2-128F" : (signatureAlgorithm.equals("SLH-DSA-SHAKE-128F") ? "SLH-DSA-SHAKE-128F" : (signatureAlgorithm.equals("SLH-DSA-SHA2-192S") ? "SLH-DSA-SHA2-192S" : (signatureAlgorithm.equals("SLH-DSA-SHAKE-192S") ? "SLH-DSA-SHAKE-192S" : (signatureAlgorithm.equals("SLH-DSA-SHA2-192F") ? "SLH-DSA-SHA2-192F" : (signatureAlgorithm.equals("SLH-DSA-SHAKE-192F") ? "SLH-DSA-SHAKE-192F" : (signatureAlgorithm.equals("SLH-DSA-SHA2-256S") ? "SLH-DSA-SHA2-256S" : (signatureAlgorithm.equals("SLH-DSA-SHAKE-256S") ? "SLH-DSA-SHAKE-256S" : (signatureAlgorithm.equals("SLH-DSA-SHA2-256F") ? "SLH-DSA-SHA2-256F" : (signatureAlgorithm.equals("SLH-DSA-SHAKE-256F") ? "SLH-DSA-SHAKE-256F" : "RSA")))))))))))))))))))))));
        return ret;
    }

    public static String getKeySpecification(PublicKey publicKey) {
        if (log.isTraceEnabled()) {
            log.trace((Object)">getKeySpecification");
        }
        Object keyspec = null;
        if (publicKey instanceof RSAPublicKey) {
            keyspec = Integer.toString(((RSAPublicKey)publicKey).getModulus().bitLength());
        } else if (publicKey instanceof ECPublicKey) {
            ECPublicKey ecPublicKey = (ECPublicKey)publicKey;
            if (ecPublicKey.getParams() instanceof ECNamedCurveSpec) {
                Object curveName;
                keyspec = ((ECNamedCurveSpec)ecPublicKey.getParams()).getName();
                if (Character.isDigit(((String)keyspec).charAt(0))) {
                    curveName = ECNamedCurveTable.getName((ASN1ObjectIdentifier)new ASN1ObjectIdentifier((String)keyspec));
                    if (curveName == null) {
                        log.warn((Object)("Failed to look up curve name for OID " + (String)keyspec));
                    } else {
                        keyspec = curveName;
                    }
                }
                if ((curveName = AlgorithmTools.getEcKeySpecAliases((String)keyspec).iterator()).hasNext()) {
                    String keySpecAlias = (String)curveName.next();
                    keyspec = keySpecAlias;
                }
            } else {
                keyspec = KEYSPEC_UNKNOWN;
                ECParameterSpec namedCurve = ecPublicKey.getParams();
                if (namedCurve != null) {
                    int c1 = namedCurve.getCofactor();
                    EllipticCurve ec1 = namedCurve.getCurve();
                    BigInteger a1 = ec1.getA();
                    BigInteger b1 = ec1.getB();
                    int fs1 = ec1.getField().getFieldSize();
                    ECPoint g1 = namedCurve.getGenerator();
                    BigInteger ax1 = g1.getAffineX();
                    BigInteger ay1 = g1.getAffineY();
                    BigInteger o1 = namedCurve.getOrder();
                    if (log.isDebugEnabled()) {
                        log.debug((Object)("a1=" + a1 + " b1=" + b1 + " fs1=" + fs1 + " ax1=" + ax1 + " ay1=" + ay1 + " o1=" + o1 + " c1=" + c1));
                    }
                    Enumeration ecNamedCurves = org.bouncycastle.jce.ECNamedCurveTable.getNames();
                    while (ecNamedCurves.hasMoreElements()) {
                        String ecNamedCurveBc = (String)ecNamedCurves.nextElement();
                        ECNamedCurveParameterSpec parameterSpec2 = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec((String)ecNamedCurveBc);
                        ECCurve ec2 = parameterSpec2.getCurve();
                        BigInteger a2 = ec2.getA().toBigInteger();
                        BigInteger b2 = ec2.getB().toBigInteger();
                        int fs2 = ec2.getFieldSize();
                        org.bouncycastle.math.ec.ECPoint g2 = parameterSpec2.getG();
                        BigInteger ax2 = g2.getAffineXCoord().toBigInteger();
                        BigInteger ay2 = g2.getAffineYCoord().toBigInteger();
                        BigInteger h2 = parameterSpec2.getH();
                        BigInteger n2 = parameterSpec2.getN();
                        if (!a1.equals(a2) || !ax1.equals(ax2) || !b1.equals(b2) || !ay1.equals(ay2) || fs1 != fs2 || !o1.equals(n2) || c1 != h2.intValue()) continue;
                        if (log.isDebugEnabled()) {
                            log.debug((Object)("a2=" + a2 + " b2=" + b2 + " fs2=" + fs2 + " ax2=" + ax2 + " ay2=" + ay2 + " h2=" + h2 + " n2=" + n2 + " " + ecNamedCurveBc));
                        }
                        keyspec = ecNamedCurveBc;
                    }
                }
            }
        } else {
            if (publicKey instanceof BCEdDSAPublicKey) {
                return publicKey.getAlgorithm();
            }
            if (publicKey instanceof FalconPublicKey) {
                return ((FalconPublicKey)publicKey).getParameterSpec().getName().toUpperCase();
            }
            if (publicKey instanceof MLKEMPublicKey) {
                return ((MLKEMPublicKey)publicKey).getParameterSpec().getName().toUpperCase();
            }
            if (publicKey instanceof MLDSAPublicKey) {
                return ((MLDSAPublicKey)publicKey).getParameterSpec().getName().toUpperCase();
            }
            if (publicKey instanceof SLHDSAPublicKey) {
                return ((SLHDSAPublicKey)publicKey).getParameterSpec().getName().toUpperCase();
            }
            if (publicKey instanceof BCLMSPublicKey) {
                return ((BCLMSPublicKey)publicKey).getAlgorithm();
            }
        }
        if (log.isTraceEnabled()) {
            log.trace((Object)("<getKeySpecification: " + (String)keyspec));
        }
        return keyspec;
    }

    @Deprecated
    public static boolean isNamedECKnownInDefaultProvider(String ecNamedCurveBc) {
        return true;
    }

    public static String getEcKeySpecOidFromBcName(String ecNamedCurveBc) {
        ASN1ObjectIdentifier oid = ECNamedCurveTable.getOID((String)ecNamedCurveBc);
        if (oid == null) {
            return ecNamedCurveBc;
        }
        return oid.getId();
    }

    public static List<String> getEcKeySpecAliases(String namedEllipticCurve) {
        if (ecKeySpecAliases != null) {
            if (ecKeySpecAliases.containsKey(namedEllipticCurve)) {
                return ecKeySpecAliases.get(namedEllipticCurve);
            }
        } else {
            ecKeySpecAliases = new HashMap<String, List<String>>();
        }
        ECNamedCurveParameterSpec parameterSpec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec((String)namedEllipticCurve);
        ArrayList<String> ret = new ArrayList<String>();
        ret.add(namedEllipticCurve);
        if (parameterSpec != null) {
            Enumeration ecNamedCurves = org.bouncycastle.jce.ECNamedCurveTable.getNames();
            while (ecNamedCurves.hasMoreElements()) {
                ECNamedCurveParameterSpec parameterSpec2;
                String currentCurve = (String)ecNamedCurves.nextElement();
                if (namedEllipticCurve.equals(currentCurve) || !parameterSpec.equals((Object)(parameterSpec2 = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec((String)currentCurve)))) continue;
                ret.add(currentCurve);
            }
        }
        ecKeySpecAliases.put(namedEllipticCurve, ret);
        return ret;
    }

    public static String getHashAlgorithm(String signatureAlgorithm) {
        String result = signatureAlgorithm.contains("SHA1") ? "SHA1" : (signatureAlgorithm.contains("SHA224") ? "SHA224" : (signatureAlgorithm.contains("SHA256") ? "SHA256" : (signatureAlgorithm.contains("SHA384") ? "SHA384" : (signatureAlgorithm.contains("SHA512") ? "SHA512" : (signatureAlgorithm.contains("SHA3-256") ? "SHA3-256" : (signatureAlgorithm.contains("SHA3-384") ? "SHA3-384" : (signatureAlgorithm.contains("SHA3-512") ? "SHA3-512" : signatureAlgorithm)))))));
        return result;
    }

    public static String getEncSigAlgFromSigAlg(String signatureAlgorithm, PublicKey publicKey) {
        String encSigAlg = signatureAlgorithm;
        block25 : switch (signatureAlgorithm) {
            case "Ed25519": 
            case "Ed448": 
            case "FALCON-512": 
            case "FALCON-1024": 
            case "ML-KEM-512": 
            case "ML-KEM-768": 
            case "ML-KEM-1024": 
            case "ML-DSA-44": 
            case "ML-DSA-65": 
            case "ML-DSA-87": 
            case "LMS": 
            case "SLH-DSA-SHA2-128S": 
            case "SLH-DSA-SHAKE-128S": 
            case "SLH-DSA-SHA2-128F": 
            case "SLH-DSA-SHAKE-128F": 
            case "SLH-DSA-SHA2-192S": 
            case "SLH-DSA-SHAKE-192S": 
            case "SLH-DSA-SHA2-192F": 
            case "SLH-DSA-SHAKE-192F": 
            case "SLH-DSA-SHA2-256S": 
            case "SLH-DSA-SHAKE-256S": 
            case "SLH-DSA-SHA2-256F": 
            case "SLH-DSA-SHAKE-256F": {
                encSigAlg = "SHA256WithRSA";
                break;
            }
            default: {
                String hashAlgo = AlgorithmTools.getHashAlgorithm(signatureAlgorithm);
                if (publicKey instanceof RSAPublicKey) {
                    if (signatureAlgorithm.contains("MGF1")) {
                        encSigAlg = signatureAlgorithm;
                        break;
                    }
                    switch (hashAlgo) {
                        case "SHA1": {
                            encSigAlg = "SHA1WithRSA";
                            break block25;
                        }
                        case "SHA224": {
                            encSigAlg = "SHA256WithRSA";
                            break block25;
                        }
                        case "SHA256": {
                            encSigAlg = "SHA256WithRSA";
                            break block25;
                        }
                        case "SHA384": {
                            encSigAlg = "SHA384WithRSA";
                            break block25;
                        }
                        case "SHA512": {
                            encSigAlg = "SHA512WithRSA";
                            break block25;
                        }
                        case "SHA3-256": {
                            encSigAlg = "SHA3-256withRSA";
                            break block25;
                        }
                        case "SHA3-384": {
                            encSigAlg = "SHA3-384withRSA";
                            break block25;
                        }
                        case "SHA3-512": {
                            encSigAlg = "SHA3-512withRSA";
                            break block25;
                        }
                    }
                    encSigAlg = signatureAlgorithm;
                    break;
                }
                if (publicKey instanceof ECPublicKey) {
                    switch (hashAlgo) {
                        case "SHA1": {
                            encSigAlg = "SHA1withECDSA";
                            break block25;
                        }
                        case "SHA224": {
                            encSigAlg = "SHA224withECDSA";
                            break block25;
                        }
                        case "SHA256": {
                            encSigAlg = "SHA256withECDSA";
                            break block25;
                        }
                        case "SHA384": {
                            encSigAlg = "SHA384withECDSA";
                            break block25;
                        }
                        case "SHA512": {
                            encSigAlg = "SHA512withECDSA";
                            break block25;
                        }
                        case "SHA3-256": {
                            encSigAlg = "SHA3-256withECDSA";
                            break block25;
                        }
                        case "SHA3-384": {
                            encSigAlg = "SHA3-384withECDSA";
                            break block25;
                        }
                        case "SHA3-512": {
                            encSigAlg = "SHA3-512withECDSA";
                            break block25;
                        }
                    }
                    encSigAlg = signatureAlgorithm;
                    break;
                }
                encSigAlg = signatureAlgorithm;
            }
        }
        return encSigAlg;
    }

    public static boolean isCompatibleSigAlg(PublicKey publicKey, String signatureAlgorithm) {
        String algname = publicKey.getAlgorithm();
        if (algname == null) {
            algname = "";
        }
        boolean ret = false;
        if (StringUtils.contains((String)signatureAlgorithm, (String)"RSA")) {
            if (publicKey instanceof RSAPublicKey) {
                ret = true;
            }
        } else if (StringUtils.contains((String)signatureAlgorithm, (String)"ECDSA")) {
            if (publicKey instanceof ECPublicKey) {
                ret = true;
            }
        } else if (StringUtils.equals((String)signatureAlgorithm, (String)"Ed25519")) {
            if (StringUtils.equals((String)"Ed25519", (String)publicKey.getAlgorithm())) {
                ret = true;
            }
        } else if (StringUtils.equals((String)signatureAlgorithm, (String)"Ed448")) {
            if (StringUtils.equals((String)"Ed448", (String)publicKey.getAlgorithm())) {
                ret = true;
            }
        } else if (StringUtils.containsIgnoreCase((String)signatureAlgorithm, (String)"FALCON")) {
            if (publicKey instanceof FalconKey) {
                ret = true;
            }
        } else if (StringUtils.containsIgnoreCase((String)signatureAlgorithm, (String)"ML-KEM")) {
            if (publicKey instanceof MLKEMKey) {
                ret = true;
            }
        } else if (StringUtils.containsIgnoreCase((String)signatureAlgorithm, (String)"ML-DSA")) {
            if (publicKey instanceof MLDSAKey) {
                ret = true;
            }
        } else if (StringUtils.containsIgnoreCase((String)signatureAlgorithm, (String)"SLH-DSA")) {
            if (publicKey instanceof SLHDSAKey) {
                ret = true;
            }
        } else if (StringUtils.containsIgnoreCase((String)signatureAlgorithm, (String)"LMS") && publicKey instanceof LMSKey) {
            ret = true;
        }
        return ret;
    }

    public static String getSignatureAlgorithm(Certificate cert) {
        String signatureAlgorithm = null;
        String certSignatureAlgorithm = CertTools.getCertSignatureAlgorithmNameAsString(cert);
        PublicKey publickey = cert.getPublicKey();
        if (publickey instanceof RSAPublicKey) {
            if (certSignatureAlgorithm.contains("SHA3-")) {
                if (certSignatureAlgorithm.contains("256")) {
                    signatureAlgorithm = "SHA3-256withRSA";
                } else if (certSignatureAlgorithm.contains("384")) {
                    signatureAlgorithm = "SHA3-384withRSA";
                } else if (certSignatureAlgorithm.contains("512")) {
                    signatureAlgorithm = "SHA3-512withRSA";
                }
            } else if (!certSignatureAlgorithm.contains("MGF1")) {
                if (certSignatureAlgorithm.contains("MD5")) {
                    signatureAlgorithm = "MD5WithRSA";
                } else if (certSignatureAlgorithm.contains("SHA1")) {
                    signatureAlgorithm = "SHA1WithRSA";
                } else if (certSignatureAlgorithm.contains("256")) {
                    signatureAlgorithm = "SHA256WithRSA";
                } else if (certSignatureAlgorithm.contains("384")) {
                    signatureAlgorithm = "SHA384WithRSA";
                } else if (certSignatureAlgorithm.contains("512")) {
                    signatureAlgorithm = "SHA512WithRSA";
                }
            } else if (certSignatureAlgorithm.contains("SHA1")) {
                signatureAlgorithm = "SHA1withRSAandMGF1";
            } else if (certSignatureAlgorithm.contains("256")) {
                signatureAlgorithm = "SHA256withRSAandMGF1";
            } else if (certSignatureAlgorithm.contains("384")) {
                signatureAlgorithm = "SHA384withRSAandMGF1";
            } else if (certSignatureAlgorithm.contains("512")) {
                signatureAlgorithm = "SHA512withRSAandMGF1";
            }
        } else if (publickey instanceof BCEdDSAPublicKey) {
            signatureAlgorithm = publickey.getAlgorithm();
        } else if (publickey instanceof FalconKey) {
            signatureAlgorithm = certSignatureAlgorithm;
        } else if (publickey instanceof MLKEMKey) {
            signatureAlgorithm = certSignatureAlgorithm;
        } else if (publickey instanceof MLDSAKey) {
            signatureAlgorithm = certSignatureAlgorithm;
        } else if (publickey instanceof SLHDSAKey) {
            signatureAlgorithm = certSignatureAlgorithm;
        } else if (certSignatureAlgorithm.contains("SHA3-")) {
            if (certSignatureAlgorithm.contains("256")) {
                return "SHA3-256withECDSA";
            }
            if (certSignatureAlgorithm.contains("384")) {
                return "SHA3-384withECDSA";
            }
            if (certSignatureAlgorithm.contains("512")) {
                return "SHA3-512withECDSA";
            }
        } else if (certSignatureAlgorithm.contains("256")) {
            signatureAlgorithm = "SHA256withECDSA";
        } else if (certSignatureAlgorithm.contains("224")) {
            signatureAlgorithm = "SHA224withECDSA";
        } else if (certSignatureAlgorithm.contains("384")) {
            signatureAlgorithm = "SHA384withECDSA";
        } else if (certSignatureAlgorithm.contains("512")) {
            signatureAlgorithm = "SHA512withECDSA";
        } else if (certSignatureAlgorithm.contains("ECDSA")) {
            signatureAlgorithm = "SHA1withECDSA";
        }
        if (log.isDebugEnabled()) {
            log.debug((Object)("getSignatureAlgorithm: " + signatureAlgorithm));
        }
        return signatureAlgorithm;
    }

    public static SignatureParameter getSignatureParameterFromOid(String oid) {
        if (oid != null && oid.equals(PKCSObjectIdentifiers.id_RSASSA_PSS.getId())) {
            return SignatureParameter.PSS;
        }
        return SignatureParameter.NONE;
    }

    public static String getDigestFromSigAlgAndHandleParameters(AlgorithmIdentifier sigAlg, String defaultDigest) {
        ASN1ObjectIdentifier oid = sigAlg.getAlgorithm();
        if (oid.equals((ASN1Primitive)PKCSObjectIdentifiers.id_RSASSA_PSS)) {
            RSASSAPSSparams pss = RSASSAPSSparams.getInstance((Object)sigAlg.getParameters());
            if (pss.getHashAlgorithm() == null || pss.getHashAlgorithm().getAlgorithm() == null) {
                return defaultDigest;
            }
            ASN1ObjectIdentifier hashOid = pss.getHashAlgorithm().getAlgorithm();
            return hashOid.getId();
        }
        String sigAlgOid = oid.getId();
        return AlgorithmTools.getDigestFromSigAlg(sigAlgOid, defaultDigest);
    }

    public static String getDigestFromSigAlg(String sigAlgOid, String defaultDigest) {
        if (sigAlgOid.equals(X9ObjectIdentifiers.ecdsa_with_SHA1.getId()) || sigAlgOid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId())) {
            return CMSSignedGenerator.DIGEST_SHA1;
        }
        if (sigAlgOid.equals(X9ObjectIdentifiers.ecdsa_with_SHA224.getId()) || sigAlgOid.equals(PKCSObjectIdentifiers.sha224WithRSAEncryption.getId())) {
            return CMSSignedGenerator.DIGEST_SHA224;
        }
        if (sigAlgOid.equals(X9ObjectIdentifiers.ecdsa_with_SHA256.getId()) || sigAlgOid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())) {
            return CMSSignedGenerator.DIGEST_SHA256;
        }
        if (sigAlgOid.equals(X9ObjectIdentifiers.ecdsa_with_SHA384.getId()) || sigAlgOid.equals(PKCSObjectIdentifiers.sha384WithRSAEncryption.getId())) {
            return CMSSignedGenerator.DIGEST_SHA384;
        }
        if (sigAlgOid.equals(X9ObjectIdentifiers.ecdsa_with_SHA512.getId()) || sigAlgOid.equals(PKCSObjectIdentifiers.sha512WithRSAEncryption.getId())) {
            return CMSSignedGenerator.DIGEST_SHA512;
        }
        if (sigAlgOid.equals(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256.getId())) {
            return NISTObjectIdentifiers.id_sha3_256.getId();
        }
        if (sigAlgOid.equals(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384.getId())) {
            return NISTObjectIdentifiers.id_sha3_384.getId();
        }
        if (sigAlgOid.equals(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512.getId())) {
            return NISTObjectIdentifiers.id_sha3_512.getId();
        }
        if (sigAlgOid.equals(NISTObjectIdentifiers.id_ecdsa_with_sha3_256.getId())) {
            return NISTObjectIdentifiers.id_sha3_256.getId();
        }
        if (sigAlgOid.equals(NISTObjectIdentifiers.id_ecdsa_with_sha3_384.getId())) {
            return NISTObjectIdentifiers.id_sha3_384.getId();
        }
        if (sigAlgOid.equals(NISTObjectIdentifiers.id_ecdsa_with_sha3_512.getId())) {
            return NISTObjectIdentifiers.id_sha3_512.getId();
        }
        if (sigAlgOid.equals(PKCSObjectIdentifiers.md5WithRSAEncryption.getId())) {
            return CMSSignedGenerator.DIGEST_MD5;
        }
        return defaultDigest;
    }

    public static ASN1ObjectIdentifier getSignAlgOidFromDigestAndKey(String digestAlg, String keyAlg) {
        if (log.isTraceEnabled()) {
            log.trace((Object)(">getSignAlg(" + digestAlg + "," + keyAlg + ")"));
        }
        ASN1ObjectIdentifier oid = PKCSObjectIdentifiers.sha256WithRSAEncryption;
        if (keyAlg.equals("EC") || keyAlg.equals("ECDSA")) {
            oid = X9ObjectIdentifiers.ecdsa_with_SHA256;
        } else if (keyAlg.equals("Ed25519")) {
            oid = EdECObjectIdentifiers.id_Ed25519;
        } else if (keyAlg.equals("Ed448")) {
            oid = EdECObjectIdentifiers.id_Ed448;
        } else if (keyAlg.equals("FALCON-512")) {
            oid = BCObjectIdentifiers.falcon_512;
        } else if (keyAlg.equals("FALCON-1024")) {
            oid = BCObjectIdentifiers.falcon_1024;
        } else if (keyAlg.equals("ML-KEM-512")) {
            oid = NISTObjectIdentifiers.id_alg_ml_kem_512;
        } else if (keyAlg.equals("ML-KEM-768")) {
            oid = NISTObjectIdentifiers.id_alg_ml_kem_768;
        } else if (keyAlg.equals("ML-KEM-1024")) {
            oid = NISTObjectIdentifiers.id_alg_ml_kem_1024;
        } else if (keyAlg.equals("ML-DSA-44")) {
            oid = NISTObjectIdentifiers.id_ml_dsa_44;
        } else if (keyAlg.equals("ML-DSA-65")) {
            oid = NISTObjectIdentifiers.id_ml_dsa_65;
        } else if (keyAlg.equals("ML-DSA-87")) {
            oid = NISTObjectIdentifiers.id_ml_dsa_87;
        } else if (keyAlg.equals("LMS")) {
            oid = PKCSObjectIdentifiers.id_alg_hss_lms_hashsig;
        } else if (keyAlg.equals("SLH-DSA-SHA2-128S")) {
            oid = NISTObjectIdentifiers.id_slh_dsa_sha2_128s;
        } else if (keyAlg.equals("SLH-DSA-SHAKE-128S")) {
            oid = NISTObjectIdentifiers.id_slh_dsa_shake_128s;
        } else if (keyAlg.equals("SLH-DSA-SHA2-128F")) {
            oid = NISTObjectIdentifiers.id_slh_dsa_sha2_128f;
        } else if (keyAlg.equals("SLH-DSA-SHAKE-128F")) {
            oid = NISTObjectIdentifiers.id_slh_dsa_shake_128f;
        } else if (keyAlg.equals("SLH-DSA-SHA2-192S")) {
            oid = NISTObjectIdentifiers.id_slh_dsa_sha2_192s;
        } else if (keyAlg.equals("SLH-DSA-SHAKE-192S")) {
            oid = NISTObjectIdentifiers.id_slh_dsa_shake_192s;
        } else if (keyAlg.equals("SLH-DSA-SHA2-192F")) {
            oid = NISTObjectIdentifiers.id_slh_dsa_sha2_192f;
        } else if (keyAlg.equals("SLH-DSA-SHAKE-192F")) {
            oid = NISTObjectIdentifiers.id_slh_dsa_shake_192f;
        } else if (keyAlg.equals("SLH-DSA-SHA2-256S")) {
            oid = NISTObjectIdentifiers.id_slh_dsa_sha2_256s;
        } else if (keyAlg.equals("SLH-DSA-SHAKE-256S")) {
            oid = NISTObjectIdentifiers.id_slh_dsa_shake_256s;
        } else if (keyAlg.equals("SLH-DSA-SHA2-256F")) {
            oid = NISTObjectIdentifiers.id_slh_dsa_sha2_256f;
        } else if (keyAlg.equals("SLH-DSA-SHAKE-256F")) {
            oid = NISTObjectIdentifiers.id_slh_dsa_shake_256f;
        }
        if (digestAlg != null) {
            if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA1) && keyAlg.equals("RSA")) {
                oid = PKCSObjectIdentifiers.sha1WithRSAEncryption;
            } else if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA256) && keyAlg.equals("RSA")) {
                oid = PKCSObjectIdentifiers.sha256WithRSAEncryption;
            } else if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA384) && keyAlg.equals("RSA")) {
                oid = PKCSObjectIdentifiers.sha384WithRSAEncryption;
            } else if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA512) && keyAlg.equals("RSA")) {
                oid = PKCSObjectIdentifiers.sha512WithRSAEncryption;
            } else if (digestAlg.equals(CMSSignedGenerator.DIGEST_MD5) && keyAlg.equals("RSA")) {
                oid = PKCSObjectIdentifiers.md5WithRSAEncryption;
            } else if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA1) && (keyAlg.equals("ECDSA") || keyAlg.equals("EC"))) {
                oid = X9ObjectIdentifiers.ecdsa_with_SHA1;
            } else if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA256) && (keyAlg.equals("ECDSA") || keyAlg.equals("EC"))) {
                oid = X9ObjectIdentifiers.ecdsa_with_SHA256;
            } else if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA224) && (keyAlg.equals("ECDSA") || keyAlg.equals("EC"))) {
                oid = X9ObjectIdentifiers.ecdsa_with_SHA224;
            } else if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA384) && (keyAlg.equals("ECDSA") || keyAlg.equals("EC"))) {
                oid = X9ObjectIdentifiers.ecdsa_with_SHA384;
            } else if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA512) && (keyAlg.equals("ECDSA") || keyAlg.equals("EC"))) {
                oid = X9ObjectIdentifiers.ecdsa_with_SHA512;
            } else if (digestAlg.equals(NISTObjectIdentifiers.id_sha3_256.toString()) && keyAlg.equals("RSA")) {
                oid = NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256;
            } else if (digestAlg.equals(NISTObjectIdentifiers.id_sha3_384.toString()) && keyAlg.equals("RSA")) {
                oid = NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384;
            } else if (digestAlg.equals(NISTObjectIdentifiers.id_sha3_512.toString()) && keyAlg.equals("RSA")) {
                oid = NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512;
            } else if (digestAlg.equals(NISTObjectIdentifiers.id_sha3_256.toString()) && (keyAlg.equals("ECDSA") || keyAlg.equals("EC"))) {
                oid = NISTObjectIdentifiers.id_ecdsa_with_sha3_256;
            } else if (digestAlg.equals(NISTObjectIdentifiers.id_sha3_384.toString()) && (keyAlg.equals("ECDSA") || keyAlg.equals("EC"))) {
                oid = NISTObjectIdentifiers.id_ecdsa_with_sha3_384;
            } else if (digestAlg.equals(NISTObjectIdentifiers.id_sha3_512.toString()) && (keyAlg.equals("ECDSA") || keyAlg.equals("EC"))) {
                oid = NISTObjectIdentifiers.id_ecdsa_with_sha3_512;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug((Object)("getSignAlgOidFromDigestAndKey: " + oid.getId()));
        }
        return oid;
    }

    public static String getAlgorithmNameFromDigestAndKey(String digestAlg, String keyAlg, SignatureParameter parameter) {
        ASN1ObjectIdentifier digestOid;
        DefaultAlgorithmNameFinder nameFinder;
        String digestName;
        if (SignatureParameter.PSS == parameter && "RSA".equalsIgnoreCase(keyAlg) && (digestName = (nameFinder = new DefaultAlgorithmNameFinder()).getAlgorithmName(digestOid = new ASN1ObjectIdentifier(digestAlg))) != null) {
            return digestName.replace("SHA-", "SHA") + "withRSAandMGF1";
        }
        return AlgorithmTools.getAlgorithmNameFromDigestAndKey(digestAlg, keyAlg);
    }

    public static String getAlgorithmNameFromDigestAndKey(String digestAlg, String keyAlg) {
        return AlgorithmTools.getAlgorithmNameFromOID(AlgorithmTools.getSignAlgOidFromDigestAndKey(digestAlg, keyAlg));
    }

    @Deprecated
    public static boolean isSigAlgEnabled(String sigAlg) {
        return true;
    }

    public static boolean isKnownAlias(String alias) {
        return !AlgorithmTools.getAllCurveAliasesFromAlias(alias).isEmpty();
    }

    public static List<String> getAllCurveAliasesFromAlias(String alias) {
        String lowerCaseAlias = alias.toLowerCase(Locale.ROOT);
        for (Map.Entry<String, List<String>> name : AlgorithmTools.getNamedEcCurvesMap(false).entrySet()) {
            String lowerCaseCanonicalName = name.getKey().toLowerCase(Locale.ROOT);
            List<String> lowerCaseAliases = StringTools.toLowerCase(name.getValue());
            if (!StringUtils.equals((String)lowerCaseAlias, (String)lowerCaseCanonicalName) && !lowerCaseAliases.contains(lowerCaseAlias)) continue;
            ArrayList<String> aliases = new ArrayList<String>((Collection)name.getValue());
            aliases.add(name.getKey());
            Collections.sort(aliases);
            return aliases;
        }
        return new ArrayList<String>();
    }

    public static String getAlgorithmNameFromOID(ASN1ObjectIdentifier sigAlgOid) {
        if (sigAlgOid.equals((ASN1Primitive)PKCSObjectIdentifiers.md5WithRSAEncryption)) {
            return "MD5WithRSA";
        }
        if (sigAlgOid.equals((ASN1Primitive)PKCSObjectIdentifiers.sha1WithRSAEncryption)) {
            return "SHA1WithRSA";
        }
        if (sigAlgOid.equals((ASN1Primitive)PKCSObjectIdentifiers.sha256WithRSAEncryption)) {
            return "SHA256WithRSA";
        }
        if (sigAlgOid.equals((ASN1Primitive)PKCSObjectIdentifiers.sha384WithRSAEncryption)) {
            return "SHA384WithRSA";
        }
        if (sigAlgOid.equals((ASN1Primitive)PKCSObjectIdentifiers.sha512WithRSAEncryption)) {
            return "SHA512WithRSA";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256)) {
            return "SHA3-256withRSA";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384)) {
            return "SHA3-384withRSA";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512)) {
            return "SHA3-512withRSA";
        }
        if (sigAlgOid.equals((ASN1Primitive)X9ObjectIdentifiers.ecdsa_with_SHA1)) {
            return "SHA1withECDSA";
        }
        if (sigAlgOid.equals((ASN1Primitive)X9ObjectIdentifiers.ecdsa_with_SHA224)) {
            return "SHA224withECDSA";
        }
        if (sigAlgOid.equals((ASN1Primitive)X9ObjectIdentifiers.ecdsa_with_SHA256)) {
            return "SHA256withECDSA";
        }
        if (sigAlgOid.equals((ASN1Primitive)X9ObjectIdentifiers.ecdsa_with_SHA384)) {
            return "SHA384withECDSA";
        }
        if (sigAlgOid.equals((ASN1Primitive)X9ObjectIdentifiers.ecdsa_with_SHA512)) {
            return "SHA512withECDSA";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_ecdsa_with_sha3_256)) {
            return "SHA3-256withECDSA";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_ecdsa_with_sha3_384)) {
            return "SHA3-384withECDSA";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_ecdsa_with_sha3_512)) {
            return "SHA3-512withECDSA";
        }
        if (sigAlgOid.equals((ASN1Primitive)EdECObjectIdentifiers.id_Ed25519)) {
            return "Ed25519";
        }
        if (sigAlgOid.equals((ASN1Primitive)EdECObjectIdentifiers.id_Ed448)) {
            return "Ed448";
        }
        if (sigAlgOid.equals((ASN1Primitive)BCObjectIdentifiers.falcon_512)) {
            return "FALCON-512";
        }
        if (sigAlgOid.equals((ASN1Primitive)BCObjectIdentifiers.falcon_1024)) {
            return "FALCON-1024";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_alg_ml_kem_512)) {
            return "ML-KEM-512";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_alg_ml_kem_768)) {
            return "ML-KEM-768";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_alg_ml_kem_1024)) {
            return "ML-KEM-1024";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_ml_dsa_44)) {
            return "ML-DSA-44";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_ml_dsa_65)) {
            return "ML-DSA-65";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_ml_dsa_87)) {
            return "ML-DSA-87";
        }
        if (sigAlgOid.equals((ASN1Primitive)PKCSObjectIdentifiers.id_alg_hss_lms_hashsig)) {
            return "LMS";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_slh_dsa_sha2_128s)) {
            return "SLH-DSA-SHA2-128S";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_slh_dsa_shake_128s)) {
            return "SLH-DSA-SHAKE-128S";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_slh_dsa_sha2_128f)) {
            return "SLH-DSA-SHA2-128F";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_slh_dsa_shake_128f)) {
            return "SLH-DSA-SHAKE-128F";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_slh_dsa_sha2_192s)) {
            return "SLH-DSA-SHA2-192S";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_slh_dsa_shake_192s)) {
            return "SLH-DSA-SHAKE-192S";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_slh_dsa_sha2_192f)) {
            return "SLH-DSA-SHA2-192F";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_slh_dsa_shake_192f)) {
            return "SLH-DSA-SHAKE-192F";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_slh_dsa_sha2_256s)) {
            return "SLH-DSA-SHA2-256S";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_slh_dsa_shake_256s)) {
            return "SLH-DSA-SHAKE-256S";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_slh_dsa_sha2_256f)) {
            return "SLH-DSA-SHA2-256F";
        }
        if (sigAlgOid.equals((ASN1Primitive)NISTObjectIdentifiers.id_slh_dsa_shake_256f)) {
            return "SLH-DSA-SHAKE-256F";
        }
        return null;
    }

    public static ASN1ObjectIdentifier getAlgorithmOIDFromName(String sigAlgName) {
        try {
            AlgorithmIdentifier aid = finder.find(sigAlgName);
            if (aid != null) {
                return aid.getAlgorithm();
            }
        }
        catch (IllegalArgumentException e) {
            log.info((Object)("Can not find an OID for algorithm name " + sigAlgName + ", returning null"));
        }
        return null;
    }

    public static org.bouncycastle.jce.spec.ECParameterSpec getEcParameterSpecFromOid(ASN1ObjectIdentifier oid) {
        if (NISTNamedCurves.getByOID((ASN1ObjectIdentifier)oid) != null) {
            X9ECParameters x9ecParameters = NISTNamedCurves.getByOID((ASN1ObjectIdentifier)oid);
            return new org.bouncycastle.jce.spec.ECParameterSpec(x9ecParameters.getCurve(), x9ecParameters.getG(), x9ecParameters.getN());
        }
        if (SECNamedCurves.getByOID((ASN1ObjectIdentifier)oid) != null) {
            X9ECParameters x9ecParameters = SECNamedCurves.getByOID((ASN1ObjectIdentifier)oid);
            return new org.bouncycastle.jce.spec.ECParameterSpec(x9ecParameters.getCurve(), x9ecParameters.getG(), x9ecParameters.getN());
        }
        if (X962NamedCurves.getByOID((ASN1ObjectIdentifier)oid) != null) {
            X9ECParameters x9ecParameters = X962NamedCurves.getByOID((ASN1ObjectIdentifier)oid);
            return new org.bouncycastle.jce.spec.ECParameterSpec(x9ecParameters.getCurve(), x9ecParameters.getG(), x9ecParameters.getN());
        }
        if (TeleTrusTNamedCurves.getByOID((ASN1ObjectIdentifier)oid) != null) {
            X9ECParameters x9ecParameters = TeleTrusTNamedCurves.getByOID((ASN1ObjectIdentifier)oid);
            return new org.bouncycastle.jce.spec.ECParameterSpec(x9ecParameters.getCurve(), x9ecParameters.getG(), x9ecParameters.getN());
        }
        if (ANSSINamedCurves.getByOID((ASN1ObjectIdentifier)oid) != null) {
            X9ECParameters x9ecParameters = ANSSINamedCurves.getByOID((ASN1ObjectIdentifier)oid);
            return new org.bouncycastle.jce.spec.ECParameterSpec(x9ecParameters.getCurve(), x9ecParameters.getG(), x9ecParameters.getN());
        }
        if (GMNamedCurves.getByOID((ASN1ObjectIdentifier)oid) != null) {
            X9ECParameters x9ecParameters = GMNamedCurves.getByOID((ASN1ObjectIdentifier)oid);
            return new org.bouncycastle.jce.spec.ECParameterSpec(x9ecParameters.getCurve(), x9ecParameters.getG(), x9ecParameters.getN());
        }
        return null;
    }

    public static MessageDigest getDigestFromAlgoName(String signatureAlgorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        if (signatureAlgorithm.startsWith("SHA1")) {
            return MessageDigest.getInstance("SHA1", "BC");
        }
        if (signatureAlgorithm.startsWith("SHA224")) {
            return MessageDigest.getInstance("SHA-224", "BC");
        }
        if (signatureAlgorithm.startsWith("SHA256")) {
            return MessageDigest.getInstance("SHA-256", "BC");
        }
        if (signatureAlgorithm.startsWith("SHA384")) {
            return MessageDigest.getInstance("SHA-384", "BC");
        }
        if (signatureAlgorithm.startsWith("SHA512")) {
            return MessageDigest.getInstance("SHA-512", "BC");
        }
        if (signatureAlgorithm.startsWith("SHA3-256")) {
            return MessageDigest.getInstance("SHA3-256", "BC");
        }
        if (signatureAlgorithm.startsWith("SHA3-384")) {
            return MessageDigest.getInstance("SHA3-384", "BC");
        }
        if (signatureAlgorithm.startsWith("SHA3-512")) {
            return MessageDigest.getInstance("SHA3-512", "BC");
        }
        if (signatureAlgorithm.equals(NISTObjectIdentifiers.id_ecdsa_with_sha3_256.getId())) {
            return MessageDigest.getInstance("SHA3-256", "BC");
        }
        if (signatureAlgorithm.equals(NISTObjectIdentifiers.id_ecdsa_with_sha3_384.getId())) {
            return MessageDigest.getInstance("SHA3-384", "BC");
        }
        if (signatureAlgorithm.equals(NISTObjectIdentifiers.id_ecdsa_with_sha3_512.getId())) {
            return MessageDigest.getInstance("SHA3-512", "BC");
        }
        throw new NoSuchAlgorithmException("The signature algorithm " + signatureAlgorithm + " uses an unsupported digest algorithm.");
    }

    public static final boolean isPQC(String name) {
        if (name == null) {
            return false;
        }
        return StringUtils.startsWithIgnoreCase((String)name, (String)"SLH-DSA") || StringUtils.startsWithIgnoreCase((String)name, (String)"ML-DSA") || StringUtils.startsWithIgnoreCase((String)name, (String)"LMS") || pqcSigAlgs.contains(name) || StringUtils.startsWithIgnoreCase((String)name, (String)"ML-KEM") || name.startsWith(NISTObjectIdentifiers.kems.getId()) || StringUtils.startsWithIgnoreCase((String)name, (String)"FALCON") || name.startsWith(BCObjectIdentifiers.falcon.getId()) || name.startsWith("1.3.9999.3");
    }

    public static final boolean isKEM(String name) {
        if (name == null) {
            return false;
        }
        return StringUtils.startsWithIgnoreCase((String)name, (String)"ML-KEM") || name.startsWith(NISTObjectIdentifiers.kems.getId());
    }

    public static final boolean isNonStandardPQC(String name) {
        if (name == null) {
            return false;
        }
        return StringUtils.startsWithIgnoreCase((String)name, (String)"FALCON") || name.startsWith(BCObjectIdentifiers.falcon.getId()) || name.startsWith("1.3.9999.3");
    }

    static {
        finder = new DefaultSignatureAlgorithmIdentifierFinder();
        pqcSigAlgs = Arrays.asList(NISTObjectIdentifiers.id_slh_dsa_sha2_128f.getId(), NISTObjectIdentifiers.id_slh_dsa_sha2_128s.getId(), NISTObjectIdentifiers.id_slh_dsa_sha2_192f.getId(), NISTObjectIdentifiers.id_slh_dsa_sha2_192s.getId(), NISTObjectIdentifiers.id_slh_dsa_sha2_256f.getId(), NISTObjectIdentifiers.id_slh_dsa_sha2_256s.getId(), NISTObjectIdentifiers.id_slh_dsa_shake_128f.getId(), NISTObjectIdentifiers.id_slh_dsa_shake_128s.getId(), NISTObjectIdentifiers.id_slh_dsa_shake_192f.getId(), NISTObjectIdentifiers.id_slh_dsa_shake_192s.getId(), NISTObjectIdentifiers.id_slh_dsa_shake_256f.getId(), NISTObjectIdentifiers.id_slh_dsa_shake_256s.getId(), NISTObjectIdentifiers.id_ml_dsa_44.getId(), NISTObjectIdentifiers.id_ml_dsa_65.getId(), NISTObjectIdentifiers.id_ml_dsa_87.getId(), PKCSObjectIdentifiers.id_alg_hss_lms_hashsig.getId());
    }
}

