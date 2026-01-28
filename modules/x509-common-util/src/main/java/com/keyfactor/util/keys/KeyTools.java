/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.commons.lang.StringUtils
 *  org.apache.log4j.Logger
 *  org.bouncycastle.asn1.ASN1Encodable
 *  org.bouncycastle.asn1.ASN1InputStream
 *  org.bouncycastle.asn1.ASN1Primitive
 *  org.bouncycastle.asn1.ASN1Sequence
 *  org.bouncycastle.asn1.DERBMPString
 *  org.bouncycastle.asn1.DERBitString
 *  org.bouncycastle.asn1.DLSequence
 *  org.bouncycastle.asn1.edec.EdECObjectIdentifiers
 *  org.bouncycastle.asn1.nist.NISTObjectIdentifiers
 *  org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
 *  org.bouncycastle.asn1.pkcs.PrivateKeyInfo
 *  org.bouncycastle.asn1.x509.AlgorithmIdentifier
 *  org.bouncycastle.asn1.x509.SubjectKeyIdentifier
 *  org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
 *  org.bouncycastle.asn1.x9.X9ECParameters
 *  org.bouncycastle.cert.X509CRLHolder
 *  org.bouncycastle.cert.bc.BcX509ExtensionUtils
 *  org.bouncycastle.cms.CMSEnvelopedData
 *  org.bouncycastle.cms.CMSEnvelopedDataGenerator
 *  org.bouncycastle.cms.CMSException
 *  org.bouncycastle.cms.CMSProcessableByteArray
 *  org.bouncycastle.cms.CMSTypedData
 *  org.bouncycastle.cms.Recipient
 *  org.bouncycastle.cms.RecipientInfoGenerator
 *  org.bouncycastle.cms.RecipientInformation
 *  org.bouncycastle.cms.RecipientInformationStore
 *  org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder
 *  org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient
 *  org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator
 *  org.bouncycastle.crypto.ec.CustomNamedCurves
 *  org.bouncycastle.crypto.util.PublicKeyFactory
 *  org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey
 *  org.bouncycastle.jcajce.interfaces.EdDSAPublicKey
 *  org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey
 *  org.bouncycastle.jcajce.interfaces.MLDSAPublicKey
 *  org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey
 *  org.bouncycastle.jcajce.interfaces.MLKEMPublicKey
 *  org.bouncycastle.jcajce.interfaces.SLHDSAPrivateKey
 *  org.bouncycastle.jcajce.interfaces.SLHDSAPublicKey
 *  org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
 *  org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey
 *  org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey
 *  org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil
 *  org.bouncycastle.jcajce.spec.EdDSAParameterSpec
 *  org.bouncycastle.jcajce.spec.MLDSAParameterSpec
 *  org.bouncycastle.jcajce.spec.MLKEMParameterSpec
 *  org.bouncycastle.jcajce.spec.SLHDSAParameterSpec
 *  org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier
 *  org.bouncycastle.jce.provider.JCEECPublicKey
 *  org.bouncycastle.jce.spec.ECNamedCurveSpec
 *  org.bouncycastle.jce.spec.ECParameterSpec
 *  org.bouncycastle.math.ec.ECCurve
 *  org.bouncycastle.openssl.PEMKeyPair
 *  org.bouncycastle.openssl.PEMParser
 *  org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
 *  org.bouncycastle.openssl.jcajce.JcaPEMWriter
 *  org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest
 *  org.bouncycastle.pqc.crypto.util.PublicKeyFactory
 *  org.bouncycastle.pqc.jcajce.interfaces.FalconPrivateKey
 *  org.bouncycastle.pqc.jcajce.interfaces.FalconPublicKey
 *  org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec
 *  org.bouncycastle.util.encoders.Base64
 *  org.bouncycastle.util.encoders.DecoderException
 *  org.bouncycastle.util.encoders.Hex
 */
package com.keyfactor.util.keys;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.RandomHelper;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.ISignOperation;
import com.keyfactor.util.keys.KeyStoreCipher;
import com.keyfactor.util.keys.SignWithWorkingAlgorithm;
import com.keyfactor.util.keys.TaskWithSigningException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPublicKey;
import org.bouncycastle.jcajce.interfaces.SLHDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.SLHDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.jcajce.interfaces.FalconPrivateKey;
import org.bouncycastle.pqc.jcajce.interfaces.FalconPublicKey;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;

public final class KeyTools {
    private static final Logger log = Logger.getLogger(KeyTools.class);
    private static final byte[] BAG_ATTRIBUTES = "Bag Attributes\n".getBytes();
    private static final byte[] FRIENDLY_NAME = "    friendlyName: ".getBytes();
    private static final byte[] SUBJECT_ATTRIBUTE = "subject=/".getBytes();
    private static final byte[] ISSUER_ATTRIBUTE = "issuer=/".getBytes();
    private static final byte[] BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----".getBytes();
    private static final byte[] END_CERTIFICATE = "-----END CERTIFICATE-----".getBytes();
    private static final byte[] BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----".getBytes();
    private static final byte[] END_PRIVATE_KEY = "-----END PRIVATE KEY-----".getBytes();
    private static final byte[] NL = "\n".getBytes();
    public static final String CA_CERT_CHAIN_ALIAS = "cacert";
    public static final String ERROR_MESSAGE_SIGNING_FAILED = "Result from signing is null.";
    public static final String ERROR_MESSAGE_VERIFICATION_FAILED = "Signature was not correctly verified.";

    private KeyTools() {
    }

    /*
     * Enabled force condition propagation
     * Lifted jumps to return sites
     */
    public static KeyPair genKeys(String keySpec, AlgorithmParameterSpec algSpec, String keyAlg) throws InvalidAlgorithmParameterException {
        KeyPairGenerator keygen;
        if (log.isTraceEnabled()) {
            log.trace((Object)(">genKeys(" + keySpec + ", " + keyAlg + ")"));
        }
        try {
            keygen = KeyPairGenerator.getInstance(keyAlg, CryptoProviderTools.getProviderNameFromAlg(keyAlg));
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algoritmo " + keyAlg + " desconhecido.", e);
        }
        catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle was not found as a provider.", e);
        }
        if (StringUtils.equals((String)keyAlg, (String)"ECDSA") || StringUtils.equals((String)keyAlg, (String)"EC")) {
            if (keySpec != null) {
                log.debug((Object)("Generating named curve ECDSA key pair: " + keySpec));
                if (ECUtil.getNamedCurveOid((String)keySpec) != null) {
                    ECGenParameterSpec bcSpec = new ECGenParameterSpec(keySpec);
                    keygen.initialize(bcSpec, RandomHelper.getInstance("BCSP800HYBRID"));
                } else {
                    X9ECParameters ecP;
                    if (log.isDebugEnabled()) {
                        log.debug((Object)("Curve did not have an OID in BC, trying to pick up Parameter spec: " + keySpec));
                    }
                    if ((ecP = CustomNamedCurves.getByName((String)keySpec)) == null) {
                        throw new InvalidAlgorithmParameterException("Can not generate EC curve, no OID and no ECParameters found: " + keySpec);
                    }
                    org.bouncycastle.jce.spec.ECParameterSpec ecSpec = new org.bouncycastle.jce.spec.ECParameterSpec(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
                    keygen.initialize((AlgorithmParameterSpec)ecSpec, RandomHelper.getInstance("BCSP800HYBRID"));
                }
            } else {
                if (algSpec == null) throw new InvalidAlgorithmParameterException("No keySpec or algSpec specified");
                log.debug((Object)("Generating ECDSA key pair from AlgorithmParameterSpec: " + algSpec));
                keygen.initialize(algSpec, RandomHelper.getInstance("BCSP800HYBRID"));
            }
        } else if (StringUtils.isNumeric((String)keySpec) && StringUtils.startsWithIgnoreCase((String)keyAlg, (String)"FALCON")) {
            FalconParameterSpec spec;
            if ("512".equals(keySpec)) {
                spec = FalconParameterSpec.falcon_512;
            } else {
                if (!"1024".equals(keySpec)) throw new InvalidAlgorithmParameterException(keySpec + " is not a valid FALCON algorithm parameter");
                spec = FalconParameterSpec.falcon_1024;
            }
            keygen.initialize((AlgorithmParameterSpec)spec);
        } else if (StringUtils.isNumeric((String)keySpec) && StringUtils.startsWithIgnoreCase((String)keyAlg, (String)"ML-KEM")) {
            MLKEMParameterSpec spec;
            if ("512".equals(keySpec)) {
                spec = MLKEMParameterSpec.ml_kem_512;
            } else if ("768".equals(keySpec)) {
                spec = MLKEMParameterSpec.ml_kem_768;
            } else {
                if (!"1024".equals(keySpec)) throw new InvalidAlgorithmParameterException(keySpec + " is not a valid ML-KEM algorithm parameter");
                spec = MLKEMParameterSpec.ml_kem_1024;
            }
            keygen.initialize((AlgorithmParameterSpec)spec);
        } else if (StringUtils.startsWithIgnoreCase((String)keyAlg, (String)"ML-DSA")) {
            MLDSAParameterSpec spec;
            if ("ML-DSA-44".equalsIgnoreCase(keyAlg)) {
                spec = MLDSAParameterSpec.ml_dsa_44;
            } else if ("ML-DSA-65".equals(keyAlg)) {
                spec = MLDSAParameterSpec.ml_dsa_65;
            } else {
                if (!"ML-DSA-87".equals(keyAlg)) throw new InvalidAlgorithmParameterException(keySpec + " is not a valid ML-DSA key algorithm specification");
                spec = MLDSAParameterSpec.ml_dsa_87;
            }
            keygen.initialize((AlgorithmParameterSpec)spec);
        } else if (StringUtils.isNumeric((String)keySpec) && !StringUtils.startsWith((String)keyAlg, (String)"Ed")) {
            int keysize = Integer.parseInt(keySpec);
            keygen.initialize(keysize);
        } else if (StringUtils.startsWithIgnoreCase((String)keyAlg, (String)"SLH-DSA")) {
            SLHDSAParameterSpec spec;
            if ("SLH-DSA-SHA2-128S".equalsIgnoreCase(keyAlg)) {
                spec = SLHDSAParameterSpec.slh_dsa_sha2_128s;
            } else if ("SLH-DSA-SHAKE-128S".equalsIgnoreCase(keyAlg)) {
                spec = SLHDSAParameterSpec.slh_dsa_shake_128s;
            } else if ("SLH-DSA-SHA2-128F".equalsIgnoreCase(keyAlg)) {
                spec = SLHDSAParameterSpec.slh_dsa_sha2_128f;
            } else if ("SLH-DSA-SHAKE-128F".equals(keyAlg)) {
                spec = SLHDSAParameterSpec.slh_dsa_shake_128f;
            } else if ("SLH-DSA-SHA2-192S".equalsIgnoreCase(keyAlg)) {
                spec = SLHDSAParameterSpec.slh_dsa_sha2_192s;
            } else if ("SLH-DSA-SHAKE-192S".equals(keyAlg)) {
                spec = SLHDSAParameterSpec.slh_dsa_shake_192s;
            } else if ("SLH-DSA-SHA2-192F".equalsIgnoreCase(keyAlg)) {
                spec = SLHDSAParameterSpec.slh_dsa_sha2_192f;
            } else if ("SLH-DSA-SHAKE-192F".equals(keyAlg)) {
                spec = SLHDSAParameterSpec.slh_dsa_shake_192f;
            } else if ("SLH-DSA-SHA2-256S".equalsIgnoreCase(keyAlg)) {
                spec = SLHDSAParameterSpec.slh_dsa_sha2_256s;
            } else if ("SLH-DSA-SHAKE-256S".equals(keyAlg)) {
                spec = SLHDSAParameterSpec.slh_dsa_shake_256s;
            } else if ("SLH-DSA-SHA2-256F".equalsIgnoreCase(keyAlg)) {
                spec = SLHDSAParameterSpec.slh_dsa_sha2_256f;
            } else {
                if (!"SLH-DSA-SHAKE-256F".equals(keyAlg)) throw new InvalidAlgorithmParameterException(keySpec + " is not a valid ML-DSA key algorithm specification");
                spec = SLHDSAParameterSpec.slh_dsa_shake_256f;
            }
            keygen.initialize((AlgorithmParameterSpec)spec);
        }
        KeyPair keys = keygen.generateKeyPair();
        if (log.isDebugEnabled()) {
            PublicKey pk = keys.getPublic();
            int len = KeyTools.getKeyLength(pk);
            log.debug((Object)("Generated " + keys.getPublic().getAlgorithm() + " keys with length " + len));
        }
        log.trace((Object)"<genKeys()");
        return keys;
    }

    public static KeyPair genKeys(String keySpec, String keyAlg) throws InvalidAlgorithmParameterException {
        return KeyTools.genKeys(keySpec, null, keyAlg);
    }

    public static byte[] encodeEcPoint(ECPoint ecPoint, EllipticCurve curve) {
        int len;
        int i;
        byte[] x = ecPoint.getAffineX().toByteArray();
        byte[] y = ecPoint.getAffineY().toByteArray();
        int xoff = 0;
        int yoff = 0;
        for (i = 0; i < x.length - 1; ++i) {
            if (x[i] == 0) continue;
            xoff = i;
            break;
        }
        for (i = 0; i < y.length - 1; ++i) {
            if (y[i] == 0) continue;
            yoff = i;
            break;
        }
        if (x.length - xoff > (len = (curve.getField().getFieldSize() + 7) / 8) || y.length - yoff > len) {
            return null;
        }
        byte[] ret = new byte[len * 2 + 1];
        ret[0] = 4;
        System.arraycopy(x, xoff, ret, 1 + len - (x.length - xoff), x.length - xoff);
        System.arraycopy(y, yoff, ret, ret.length - (y.length - yoff), y.length - yoff);
        return ret;
    }

    public static ECPoint decodeEcPoint(byte[] encodedKey, EllipticCurve curve) {
        int length = (curve.getField().getFieldSize() + 7) / 8;
        if (encodedKey.length != 2 * length + 1 || encodedKey[0] != 4) {
            return null;
        }
        byte[] x = new byte[length];
        byte[] y = new byte[length];
        System.arraycopy(encodedKey, 1, x, 0, length);
        System.arraycopy(encodedKey, length + 1, y, 0, length);
        return new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public static byte[] encodeEd25519PublicKey(PublicKey edPublicKey) {
        byte[] byArray;
        ASN1InputStream asn1InputStream = new ASN1InputStream(edPublicKey.getEncoded());
        try {
            DLSequence id = (DLSequence)asn1InputStream.readObject();
            DERBitString raw = (DERBitString)id.getObjectAt(1).toASN1Primitive();
            byArray = raw.getBytes();
        }
        catch (Throwable throwable) {
            try {
                asn1InputStream.close();
                throw throwable;
            }
            catch (IOException e) {
                throw new IllegalStateException("IOException encountered when encoding Ed25519 key.");
            }
        }
        asn1InputStream.close();
        return byArray;
    }

    public static PublicKey decodeEd25519PublicKey(byte[] keyBody) {
        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance(EdECObjectIdentifiers.id_Ed25519.getId(), "BC");
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Ed25519 was not found as an algorithm", e);
        }
        catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle was not found as a provider.", e);
        }
        SubjectPublicKeyInfo pubKeyInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), keyBody);
        try {
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyInfo.getEncoded());
            return keyFactory.generatePublic(x509KeySpec);
        }
        catch (IOException | InvalidKeySpecException e) {
            throw new IllegalStateException("Couldn't decode Ed25519 public key", e);
        }
    }

    public static int getKeyLength(PublicKey pk) {
        if (pk instanceof RSAPublicKey) {
            RSAPublicKey rsapub = (RSAPublicKey)pk;
            return rsapub.getModulus().bitLength();
        }
        if (pk instanceof JCEECPublicKey) {
            JCEECPublicKey ecpriv = (JCEECPublicKey)pk;
            org.bouncycastle.jce.spec.ECParameterSpec spec = ecpriv.getParameters();
            if (spec != null) {
                return spec.getN().bitLength();
            }
            return 0;
        }
        if (pk instanceof BCECPublicKey) {
            BCECPublicKey ecpriv = (BCECPublicKey)pk;
            org.bouncycastle.jce.spec.ECParameterSpec spec = ecpriv.getParameters();
            if (spec != null) {
                return spec.getN().bitLength();
            }
            return 0;
        }
        if (pk instanceof ECPublicKey) {
            ECPublicKey ecpriv = (ECPublicKey)pk;
            ECParameterSpec spec = ecpriv.getParams();
            if (spec != null) {
                return spec.getOrder().bitLength();
            }
            return 0;
        }
        if (pk instanceof BCEdDSAPublicKey) {
            String algo;
            switch (algo = pk.getAlgorithm()) {
                case "Ed25519": {
                    return 255;
                }
                case "Ed448": {
                    return 448;
                }
            }
        }
        if (pk instanceof FalconPublicKey) {
            if (FalconParameterSpec.falcon_512.equals(((FalconPublicKey)pk).getParameterSpec())) {
                return 128;
            }
            if (FalconParameterSpec.falcon_1024.equals(((FalconPublicKey)pk).getParameterSpec())) {
                return 256;
            }
        }
        if (pk instanceof MLKEMPublicKey) {
            if (MLKEMParameterSpec.ml_kem_512.equals(((MLKEMPublicKey)pk).getParameterSpec())) {
                return 128;
            }
            if (MLKEMParameterSpec.ml_kem_768.equals(((MLKEMPublicKey)pk).getParameterSpec())) {
                return 192;
            }
            if (MLKEMParameterSpec.ml_kem_1024.equals(((MLKEMPublicKey)pk).getParameterSpec())) {
                return 256;
            }
        }
        if (pk instanceof MLDSAPublicKey) {
            if (MLDSAParameterSpec.ml_dsa_44.equals(((MLDSAPublicKey)pk).getParameterSpec())) {
                return 128;
            }
            if (MLDSAParameterSpec.ml_dsa_65.equals(((MLDSAPublicKey)pk).getParameterSpec())) {
                return 192;
            }
            if (MLDSAParameterSpec.ml_dsa_87.equals(((MLDSAPublicKey)pk).getParameterSpec())) {
                return 256;
            }
        }
        if (pk instanceof SLHDSAPublicKey) {
            SLHDSAParameterSpec slhdsaParameterSpec = ((SLHDSAPublicKey)pk).getParameterSpec();
            if (List.of(SLHDSAParameterSpec.slh_dsa_sha2_128s, SLHDSAParameterSpec.slh_dsa_shake_128s, SLHDSAParameterSpec.slh_dsa_sha2_128f, SLHDSAParameterSpec.slh_dsa_shake_128f).contains(slhdsaParameterSpec)) {
                return 128;
            }
            if (List.of(SLHDSAParameterSpec.slh_dsa_sha2_192s, SLHDSAParameterSpec.slh_dsa_shake_192s, SLHDSAParameterSpec.slh_dsa_sha2_192f, SLHDSAParameterSpec.slh_dsa_shake_192f).contains(slhdsaParameterSpec)) {
                return 192;
            }
            if (List.of(SLHDSAParameterSpec.slh_dsa_sha2_256s, SLHDSAParameterSpec.slh_dsa_shake_256s, SLHDSAParameterSpec.slh_dsa_sha2_256f, SLHDSAParameterSpec.slh_dsa_shake_256f).contains(slhdsaParameterSpec)) {
                return 256;
            }
        }
        return -1;
    }

    public static AlgorithmParameterSpec getKeyGenSpec(PublicKey pk) {
        if (pk == null) {
            return null;
        }
        if (pk instanceof RSAPublicKey) {
            log.debug((Object)"getKeyGenSpec: RSA");
            RSAPublicKey rpk = (RSAPublicKey)pk;
            return new RSAKeyGenParameterSpec(KeyTools.getKeyLength(pk), rpk.getPublicExponent());
        }
        if (pk instanceof ECPublicKey) {
            log.debug((Object)"getKeyGenSpec: ECPublicKey");
            ECPublicKey ecpub = (ECPublicKey)pk;
            ECParameterSpec sunsp = ecpub.getParams();
            EllipticCurve ecurve = new EllipticCurve(sunsp.getCurve().getField(), sunsp.getCurve().getA(), sunsp.getCurve().getB());
            ECParameterSpec params = new ECParameterSpec(ecurve, sunsp.getGenerator(), sunsp.getOrder(), sunsp.getCofactor());
            if (log.isDebugEnabled()) {
                log.debug((Object)("Fieldsize: " + params.getCurve().getField().getFieldSize()));
                EllipticCurve curve = params.getCurve();
                log.debug((Object)("CurveA: " + curve.getA().toString(16)));
                log.debug((Object)("CurveB: " + curve.getB().toString(16)));
                log.debug((Object)("CurveSeed: " + curve.getSeed()));
                ECFieldFp field = (ECFieldFp)curve.getField();
                log.debug((Object)("CurveSfield: " + field.getP().toString(16)));
                ECPoint p = params.getGenerator();
                log.debug((Object)("Generator: " + p.getAffineX().toString(16) + ", " + p.getAffineY().toString(16)));
                log.debug((Object)("Order: " + params.getOrder().toString(16)));
                log.debug((Object)("CoFactor: " + params.getCofactor()));
            }
            return params;
        }
        if (pk instanceof JCEECPublicKey) {
            log.debug((Object)"getKeyGenSpec: JCEECPublicKey");
            JCEECPublicKey ecpub = (JCEECPublicKey)pk;
            org.bouncycastle.jce.spec.ECParameterSpec bcsp = ecpub.getParameters();
            ECCurve curve = bcsp.getCurve();
            ECNamedCurveSpec params = new ECNamedCurveSpec(null, curve, bcsp.getG(), bcsp.getN(), bcsp.getH());
            return params;
        }
        if (pk instanceof BCEdDSAPublicKey) {
            log.debug((Object)"getKeyGenSpec: BCEdDSAPublicKey");
            EdDSAParameterSpec edSpec = new EdDSAParameterSpec(pk.getAlgorithm());
            return edSpec;
        }
        if (pk instanceof FalconPublicKey) {
            log.debug((Object)"getKeyGenSpec: FalconPublicKey");
            FalconParameterSpec spec = ((FalconPublicKey)pk).getParameterSpec();
            return spec;
        }
        if (pk instanceof MLKEMPublicKey) {
            log.debug((Object)"getKeyGenSpec: MLKEMPublicKey");
            MLKEMParameterSpec spec = ((MLKEMPublicKey)pk).getParameterSpec();
            return spec;
        }
        if (pk instanceof MLDSAPublicKey) {
            log.debug((Object)"getKeyGenSpec: MLDSAPublicKey");
            MLDSAParameterSpec spec = ((MLDSAPublicKey)pk).getParameterSpec();
            return spec;
        }
        if (pk instanceof SLHDSAPublicKey) {
            log.debug((Object)"getKeyGenSpec: SLHDSAPublicKey");
            SLHDSAParameterSpec spec = ((SLHDSAPublicKey)pk).getParameterSpec();
            return spec;
        }
        return null;
    }

    @Deprecated(forRemoval=true)
    public static KeyStore createP12(String alias, PrivateKey privKey, Certificate cert, Certificate cacert, KeyStoreCipher keyStoreCipher) throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (!(cert instanceof X509Certificate) || !(cacert instanceof X509Certificate)) {
            throw new IllegalStateException("createP12 method has been called for a non X509Certificate certificate type");
        }
        return KeyTools.createP12(alias, privKey, (X509Certificate)cert, (X509Certificate)cacert, keyStoreCipher);
    }

    public static KeyStore createP12(String alias, PrivateKey privKey, X509Certificate cert, X509Certificate cacert, KeyStoreCipher keyStoreCipher) throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        X509Certificate[] chain = cacert == null ? null : new X509Certificate[]{cacert};
        return KeyTools.createP12(alias, privKey, cert, chain, keyStoreCipher);
    }

    @Deprecated
    public static KeyStore createP12(String alias, PrivateKey privKey, Certificate cert, Collection<Certificate> cacerts, KeyStoreCipher keyStoreCipher) throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        Certificate[] chain = cacerts == null ? null : cacerts.toArray(new Certificate[cacerts.size()]);
        return KeyTools.createP12(alias, privKey, cert, chain, keyStoreCipher);
    }

    public static KeyStore createP12(String alias, PrivateKey privKey, X509Certificate cert, Collection<X509Certificate> cacerts, KeyStoreCipher keyStoreCipher) throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        X509Certificate[] chain = cacerts == null ? null : cacerts.toArray(new X509Certificate[cacerts.size()]);
        return KeyTools.createP12(alias, privKey, cert, chain, keyStoreCipher);
    }

    @Deprecated(forRemoval=true)
    public static KeyStore createP12(String alias, PrivateKey privateKey, Certificate certificate, Certificate[] caCertificateChain, KeyStoreCipher keyStoreCipher) throws CertificateEncodingException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyTools.createP12(alias, privateKey, (X509Certificate)certificate, (X509Certificate[])caCertificateChain, keyStoreCipher);
    }

    public static KeyStore createP12(String alias, PrivateKey privateKey, X509Certificate certificate, X509Certificate[] caCertificateChain, KeyStoreCipher keyStoreCipher) throws CertificateEncodingException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            KeyStore store = KeyStore.getInstance(keyStoreCipher.getLabel(), "BC");
            store.load(null, null);
            return KeyTools.createP12(alias, privateKey, certificate, caCertificateChain, store);
        }
        catch (IOException | KeyStoreException | NoSuchProviderException e) {
            throw new IllegalStateException(e);
        }
    }

    private static KeyStore createP12(String alias, PrivateKey privateKey, PrivateKey alternativePrivateKey, X509Certificate certificate, X509Certificate[] caCertificateChain, KeyStoreCipher keyStoreCipher) throws CertificateEncodingException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            KeyStore store = KeyStore.getInstance(keyStoreCipher.getLabel(), "BC");
            store.load(null, null);
            return KeyTools.createP12(alias, privateKey, alternativePrivateKey, certificate, caCertificateChain, store);
        }
        catch (IOException | KeyStoreException | NoSuchProviderException e) {
            throw new IllegalStateException(e);
        }
    }

    @Deprecated(forRemoval=true)
    public static KeyStore createBcfks(String alias, PrivateKey privateKey, Certificate certificate, Certificate[] caCertificateChain) throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyTools.createBcfks(alias, privateKey, (X509Certificate)certificate, (X509Certificate[])caCertificateChain);
    }

    public static KeyStore createBcfks(String alias, PrivateKey privateKey, X509Certificate certificate, X509Certificate[] caCertificateChain) throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            KeyStore store = KeyStore.getInstance("BCFKS", CryptoProviderTools.getProviderNameFromAlg(privateKey.getAlgorithm()));
            store.load(null, null);
            return KeyTools.createP12(alias, privateKey, certificate, caCertificateChain, store);
        }
        catch (IOException | KeyStoreException | NoSuchProviderException e) {
            throw new IllegalStateException(e);
        }
    }

    private static KeyStore createP12(String alias, PrivateKey privateKey, X509Certificate certificate, X509Certificate[] caCertificateChain, KeyStore store) throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyTools.createP12(alias, privateKey, null, certificate, caCertificateChain, store);
    }

    private static KeyStore createP12(String alias, PrivateKey privateKey, PrivateKey alternativePrivateKey, X509Certificate certificate, X509Certificate[] caCertificateChain, KeyStore store) throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        int i;
        if (log.isTraceEnabled()) {
            log.trace((Object)(">createP12: alias=" + alias + ", privateKey, alternativePrivateKey, certificate=" + CertTools.getSubjectDN(certificate) + ", caCertificateChain.length=" + (caCertificateChain == null ? 0 : caCertificateChain.length)));
        }
        if (certificate == null) {
            throw new IllegalArgumentException("Parameter certificate cannot be null.");
        }
        int len = 1;
        if (caCertificateChain != null) {
            len += caCertificateChain.length;
        }
        Certificate[] chain = new Certificate[len];
        CertificateFactory cf = CertTools.getCertificateFactory();
        chain[0] = cf.generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
        if (caCertificateChain != null) {
            for (i = 0; i < caCertificateChain.length; ++i) {
                X509Certificate tmpcert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(caCertificateChain[i].getEncoded()));
                chain[i + 1] = tmpcert;
            }
        }
        if (chain.length > 1) {
            for (i = 1; i < chain.length; ++i) {
                X509Certificate cacert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(chain[i].getEncoded()));
                try {
                    PKCS12BagAttributeCarrier caBagAttr = (PKCS12BagAttributeCarrier)chain[i];
                    Object cafriendly = DnComponents.getPartFromDN(CertTools.getSubjectDN(cacert), "CN");
                    if (cafriendly == null) {
                        cafriendly = DnComponents.getPartFromDN(CertTools.getSubjectDN(cacert), "O");
                        cafriendly = cafriendly == null ? ((cafriendly = DnComponents.getPartFromDN(CertTools.getSubjectDN(cacert), "OU")) == null ? "CA_unknown" + i : (String)cafriendly + i) : (String)cafriendly + i;
                    }
                    caBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, (ASN1Encodable)new DERBMPString((String)cafriendly));
                    continue;
                }
                catch (ClassCastException e) {
                    log.error((Object)"ClassCastException setting BagAttributes, can not set friendly name: ", (Throwable)e);
                }
            }
        }
        try {
            PKCS12BagAttributeCarrier certBagAttr = (PKCS12BagAttributeCarrier)chain[0];
            certBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, (ASN1Encodable)new DERBMPString(alias));
            certBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, (ASN1Encodable)KeyTools.createSubjectKeyId(chain[0].getPublicKey()));
        }
        catch (ClassCastException e) {
            log.error((Object)"ClassCastException setting BagAttributes, can not set friendly name: ", (Throwable)e);
        }
        try {
            PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance((Object)privateKey.getEncoded());
            PrivateKeyInfo v1PkInfo = new PrivateKeyInfo(pkInfo.getPrivateKeyAlgorithm(), pkInfo.getPrivateKey().getOctets());
            KeyFactory keyfact = KeyFactory.getInstance(privateKey.getAlgorithm(), CryptoProviderTools.getProviderNameFromAlg(privateKey.getAlgorithm()));
            PrivateKey pk = keyfact.generatePrivate(new PKCS8EncodedKeySpec(v1PkInfo.getEncoded()));
            store.setKeyEntry(alias, pk, null, chain);
            if (alternativePrivateKey != null) {
                PrivateKeyInfo altPkInfo = PrivateKeyInfo.getInstance((Object)alternativePrivateKey.getEncoded());
                PrivateKeyInfo altV1PkInfo = new PrivateKeyInfo(altPkInfo.getPrivateKeyAlgorithm(), altPkInfo.getPrivateKey().getOctets());
                KeyFactory altKeyfact = KeyFactory.getInstance(alternativePrivateKey.getAlgorithm(), CryptoProviderTools.getProviderNameFromAlg(alternativePrivateKey.getAlgorithm()));
                PrivateKey altPK = altKeyfact.generatePrivate(new PKCS8EncodedKeySpec(altV1PkInfo.getEncoded()));
                store.setKeyEntry(alias, altPK, null, chain);
                throw new UnsupportedOperationException("Hybrid keystore support is not fully implemented yet");
            }
            if (log.isTraceEnabled()) {
                log.trace((Object)("<createP12: alias=" + alias + ", privateKey, alternativePrivateKey, certificate=" + CertTools.getSubjectDN(certificate) + ", caCertificateChain.length=" + (caCertificateChain == null ? 0 : caCertificateChain.length)));
            }
            return store;
        }
        catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle provider was not found.", e);
        }
        catch (KeyStoreException e) {
            throw new IllegalStateException("PKCS12 keystore type could not be instanced.", e);
        }
        catch (IOException e) {
            throw new IllegalStateException("IOException should not be thrown when instancing an empty keystore.", e);
        }
    }

    public static KeyStore createJKS(String alias, PrivateKey privKey, String password, X509Certificate cert, Certificate[] cachain) throws KeyStoreException {
        KeyStore store;
        if (log.isTraceEnabled()) {
            log.trace((Object)(">createJKS: alias=" + alias + ", privKey, cert=" + CertTools.getSubjectDN(cert) + ", cachain.length=" + (cachain == null ? 0 : cachain.length)));
        }
        String caAlias = CA_CERT_CHAIN_ALIAS;
        if (cert == null) {
            throw new IllegalArgumentException("Parameter cert cannot be null.");
        }
        int len = 1;
        if (cachain != null) {
            len += cachain.length;
        }
        Certificate[] chain = new Certificate[len];
        chain[0] = cert;
        if (cachain != null) {
            System.arraycopy(cachain, 0, chain, 1, cachain.length);
        }
        try {
            store = KeyStore.getInstance("JKS");
        }
        catch (KeyStoreException e) {
            throw new IllegalStateException("No JKS implementation found in provider", e);
        }
        try {
            store.load(null, null);
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        catch (CertificateException e) {
            throw new IllegalStateException(e);
        }
        catch (IOException e) {
            throw new IllegalStateException(e);
        }
        Certificate[] usercert = new X509Certificate[]{cert};
        try {
            store.setKeyEntry(alias, privKey, password.toCharArray(), usercert);
        }
        catch (KeyStoreException e) {
            throw new IllegalStateException("Keystore apparently hasn't been loaded?", e);
        }
        if (cachain != null) {
            if (!CertTools.isSelfSigned(cachain[cachain.length - 1])) {
                throw new IllegalArgumentException("Root cert is not self-signed.");
            }
            store.setCertificateEntry(CA_CERT_CHAIN_ALIAS, cachain[cachain.length - 1]);
        }
        log.debug((Object)("Storing cert chain of length " + chain.length));
        store.setKeyEntry(alias, privKey, password.toCharArray(), chain);
        if (log.isTraceEnabled()) {
            log.trace((Object)("<createJKS: alias=" + alias + ", privKey, cert=" + CertTools.getSubjectDN(cert) + ", cachain.length=" + (cachain == null ? 0 : cachain.length)));
        }
        return store;
    }

    public static byte[] getSinglePemFromKeyStore(KeyStore ks, char[] password) throws KeyStoreException, CertificateEncodingException, IOException, UnrecoverableKeyException, NoSuchAlgorithmException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Enumeration<String> e = ks.aliases();
        String o = null;
        String alias = "";
        Key serverPrivKey = null;
        while (e.hasMoreElements()) {
            o = e.nextElement();
            if (!(o instanceof String) || !ks.isKeyEntry(o) || (serverPrivKey = (PrivateKey)ks.getKey(o, password)) == null) continue;
            alias = o;
            break;
        }
        byte[] privKeyEncoded = serverPrivKey != null ? serverPrivKey.getEncoded() : "".getBytes();
        Certificate[] chain = KeyTools.getCertChain(ks, o);
        X509Certificate userX509Certificate = (X509Certificate)chain[0];
        byte[] output = userX509Certificate.getEncoded();
        String sn = CertTools.getSubjectDN(userX509Certificate);
        String subjectdnpem = sn.replace(',', '/');
        String issuerdnpem = CertTools.getIssuerDN(userX509Certificate).replace(',', '/');
        buffer.write(BAG_ATTRIBUTES);
        buffer.write(FRIENDLY_NAME);
        buffer.write(alias.getBytes());
        buffer.write(NL);
        buffer.write(BEGIN_PRIVATE_KEY);
        buffer.write(NL);
        byte[] privKey = Base64.encode(privKeyEncoded);
        buffer.write(privKey);
        buffer.write(NL);
        buffer.write(END_PRIVATE_KEY);
        buffer.write(NL);
        buffer.write(BAG_ATTRIBUTES);
        buffer.write(FRIENDLY_NAME);
        buffer.write(alias.getBytes());
        buffer.write(NL);
        buffer.write(SUBJECT_ATTRIBUTE);
        buffer.write(subjectdnpem.getBytes());
        buffer.write(NL);
        buffer.write(ISSUER_ATTRIBUTE);
        buffer.write(issuerdnpem.getBytes());
        buffer.write(NL);
        buffer.write(BEGIN_CERTIFICATE);
        buffer.write(NL);
        byte[] userCertB64 = Base64.encode(output);
        buffer.write(userCertB64);
        buffer.write(NL);
        buffer.write(END_CERTIFICATE);
        buffer.write(NL);
        if (!CertTools.isSelfSigned(userX509Certificate)) {
            for (int num = 1; num < chain.length; ++num) {
                X509Certificate tmpX509Cert = (X509Certificate)chain[num];
                String sn2 = CertTools.getSubjectDN(tmpX509Cert);
                String cnTmp = DnComponents.getPartFromDN(sn2, "CN");
                String cn = StringUtils.isEmpty((String)cnTmp) ? cnTmp : "Unknown";
                String subjectdnpem2 = sn2.replace(',', '/');
                String issuerdnpem2 = CertTools.getIssuerDN(tmpX509Cert).replace(',', '/');
                buffer.write(BAG_ATTRIBUTES);
                buffer.write(FRIENDLY_NAME);
                buffer.write(cn.getBytes());
                buffer.write(NL);
                buffer.write(SUBJECT_ATTRIBUTE);
                buffer.write(subjectdnpem2.getBytes());
                buffer.write(NL);
                buffer.write(ISSUER_ATTRIBUTE);
                buffer.write(issuerdnpem2.getBytes());
                buffer.write(NL);
                byte[] tmpOutput = tmpX509Cert.getEncoded();
                buffer.write(BEGIN_CERTIFICATE);
                buffer.write(NL);
                byte[] tmpCACertB64 = Base64.encode(tmpOutput);
                buffer.write(tmpCACertB64);
                buffer.write(NL);
                buffer.write(END_CERTIFICATE);
                buffer.write(NL);
            }
        }
        return buffer.toByteArray();
    }

    public static String getAsPem(PublicKey publicKey) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter((Writer)new OutputStreamWriter(baos));){
            pemWriter.writeObject((Object)publicKey);
        }
        return new String(baos.toByteArray(), StandardCharsets.UTF_8);
    }

    public static String getAsPem(X509CRLHolder crl) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter((Writer)new OutputStreamWriter(baos));){
            pemWriter.writeObject((Object)crl);
        }
        return new String(baos.toByteArray(), StandardCharsets.UTF_8);
    }

    public static Certificate[] getCertChain(KeyStore keyStore, String privateKeyAlias) throws KeyStoreException {
        X509Certificate cert;
        String ialias;
        Certificate[] chain1;
        Certificate[] certchain;
        if (log.isTraceEnabled()) {
            log.trace((Object)(">getCertChain: alias='" + privateKeyAlias + "'"));
        }
        if ((certchain = keyStore.getCertificateChain(privateKeyAlias)) == null) {
            return null;
        }
        log.debug((Object)("Certchain retrieved from alias '" + privateKeyAlias + "' has length " + certchain.length));
        if (certchain.length < 1) {
            log.error((Object)("Cannot load certificate chain with alias '" + privateKeyAlias + "' from keystore."));
            if (log.isTraceEnabled()) {
                log.trace((Object)("<getCertChain: alias='" + privateKeyAlias + "', retlength=" + certchain.length));
            }
            return certchain;
        }
        if (certchain.length > 0 && CertTools.isSelfSigned(certchain[certchain.length - 1])) {
            if (log.isDebugEnabled()) {
                log.debug((Object)("Issuer (self signed)='" + CertTools.getIssuerDN(certchain[certchain.length - 1]) + "'."));
                log.debug((Object)("Subject (self signed)='" + CertTools.getSubjectDN(certchain[certchain.length - 1]) + "'."));
            }
            if (log.isTraceEnabled()) {
                log.trace((Object)("<getCertChain: alias='" + privateKeyAlias + "', retlength=" + certchain.length));
            }
            return certchain;
        }
        ArrayList<Certificate> array = new ArrayList<Certificate>();
        for (int i = 0; i < certchain.length; ++i) {
            array.add(certchain[i]);
        }
        while ((chain1 = keyStore.getCertificateChain(ialias = DnComponents.getPartFromDN(CertTools.getIssuerDN(cert = (X509Certificate)array.get(array.size() - 1)), "CN"))) != null) {
            if (log.isDebugEnabled()) {
                log.debug((Object)("Loaded certificate chain with length " + chain1.length + " with alias '" + ialias + "'."));
            }
            if (chain1.length == 0) {
                log.error((Object)"No RootCA certificate found!");
                break;
            }
            boolean isSelfSigned = false;
            for (int j = 0; j < chain1.length && !isSelfSigned; ++j) {
                array.add(chain1[j]);
                if (!CertTools.isSelfSigned(chain1[j])) continue;
                isSelfSigned = true;
            }
            if (!isSelfSigned) continue;
            break;
        }
        Certificate[] ret = new Certificate[array.size()];
        for (int i = 0; i < ret.length; ++i) {
            ret[i] = (Certificate)array.get(i);
            if (!log.isTraceEnabled()) continue;
            log.trace((Object)("Issuer='" + CertTools.getIssuerDN(ret[i]) + "'."));
            log.trace((Object)("Subject='" + CertTools.getSubjectDN(ret[i]) + "'."));
        }
        if (log.isTraceEnabled()) {
            log.trace((Object)("<getCertChain: alias='" + privateKeyAlias + "', retlength=" + ret.length));
        }
        return ret;
    }

    public static SubjectKeyIdentifier createSubjectKeyId(PublicKey pubKey) {
        SubjectKeyIdentifier subjectKeyIdentifier;
        ASN1InputStream pubKeyAsn1InputStream = new ASN1InputStream((InputStream)new ByteArrayInputStream(pubKey.getEncoded()));
        try {
            ASN1Sequence keyASN1Sequence;
            ASN1Primitive keyObject = pubKeyAsn1InputStream.readObject();
            if (keyObject instanceof ASN1Sequence) {
                keyASN1Sequence = (ASN1Sequence)keyObject;
            } else {
                PublicKey altKey = (PublicKey)KeyFactory.getInstance(pubKey.getAlgorithm(), CryptoProviderTools.getProviderNameFromAlg(pubKey.getAlgorithm())).translateKey(pubKey);
                try (ASN1InputStream altKeyAsn1InputStream = new ASN1InputStream((InputStream)new ByteArrayInputStream(altKey.getEncoded()));){
                    keyASN1Sequence = (ASN1Sequence)altKeyAsn1InputStream.readObject();
                }
            }
            BcX509ExtensionUtils x509ExtensionUtils = new BcX509ExtensionUtils();
            subjectKeyIdentifier = x509ExtensionUtils.createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance((Object)keyASN1Sequence));
        }
        catch (Throwable throwable) {
            try {
                try {
                    pubKeyAsn1InputStream.close();
                }
                catch (Throwable throwable2) {
                    throwable.addSuppressed(throwable2);
                }
                throw throwable;
            }
            catch (Exception e) {
                RuntimeException e2 = new RuntimeException("error creating key");
                e2.initCause(e);
                throw e2;
            }
        }
        pubKeyAsn1InputStream.close();
        return subjectKeyIdentifier;
    }

    public static byte[] signData(PrivateKey privateKey, String signatureAlgorithm, byte[] data) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
        Signature signer = Signature.getInstance(signatureAlgorithm, CryptoProviderTools.getProviderNameFromAlg(privateKey.getAlgorithm()));
        signer.initSign(privateKey);
        signer.update(data);
        return signer.sign();
    }

    public static boolean verifyData(PublicKey publicKey, String signatureAlgorithm, byte[] data, byte[] signature) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
        Signature signer = Signature.getInstance(signatureAlgorithm, CryptoProviderTools.getProviderNameFromAlg(publicKey.getAlgorithm()));
        signer.initVerify(publicKey);
        signer.update(data);
        return signer.verify(signature);
    }

    private static Provider getProvider(String sProvider) {
        if (sProvider == null) {
            return Security.getProvider("BC");
        }
        Provider provider = Security.getProvider(sProvider);
        if (provider != null) {
            return provider;
        }
        return Security.getProvider("BC");
    }

    public static void testKey(PrivateKey priv, PublicKey pub, String sProvider) throws InvalidKeyException {
        byte[] input = "Lillan gick pa vagen ut, motte dar en katt...".getBytes();
        try {
            Signature signature;
            if (log.isDebugEnabled()) {
                StringWriter sw = new StringWriter();
                try (PrintWriter pw = new PrintWriter(sw);){
                    pw.println("Testing a key:");
                    pw.println(String.format("\tTesting keys with algorithm: %s", pub.getAlgorithm()));
                    pw.println(String.format("\tprovider: %s", sProvider));
                    pw.println(String.format("\tprivateKey: %s", priv));
                    pw.println(String.format("\tprivateKey class: %s", priv.getClass().getName()));
                    pw.println(String.format("\tpublicKey: %s", pub));
                    pw.println(String.format("\tpublicKey class: %s", pub.getClass().getName()));
                    pw.flush();
                }
                log.debug((Object)sw.toString());
            }
            SignDataOperation operation = new SignDataOperation(priv, input);
            List<String> availableSignAlgorithms = AlgorithmTools.getSignatureAlgorithms(pub);
            String sigProvName = "BC".equals(sProvider) ? CryptoProviderTools.getProviderNameFromAlg(pub.getAlgorithm()) : sProvider;
            SignWithWorkingAlgorithm.doSignTask(availableSignAlgorithms, KeyTools.getProvider(sigProvName), (ISignOperation)operation);
            byte[] signBV = operation.getSignature();
            String testSigAlg = operation.getSignatureAlgorithm();
            if (signBV == null) {
                throw new InvalidKeyException(ERROR_MESSAGE_SIGNING_FAILED);
            }
            if (log.isDebugEnabled()) {
                log.debug((Object)("Created signature of size: " + signBV.length));
                log.debug((Object)("Created signature: " + new String(Hex.encode((byte[])signBV))));
            }
            String provider = CryptoProviderTools.getProviderNameFromAlg(testSigAlg);
            try {
                signature = Signature.getInstance(testSigAlg, provider);
            }
            catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                throw new IllegalStateException(provider + " was not found as a provider.", e);
            }
            signature.initVerify(pub);
            signature.update(input);
            if (!signature.verify(signBV)) {
                throw new InvalidKeyException(ERROR_MESSAGE_VERIFICATION_FAILED);
            }
        }
        catch (InvalidKeyException e) {
            throw e;
        }
        catch (TaskWithSigningException | SignatureException e) {
            throw new InvalidKeyException(String.format("Exception testing key: %s", e.getMessage()), e);
        }
    }

    public static boolean testEncryptionDecryptionKeys(PublicKey pubKey, PrivateKey privKey, String provider) throws InvalidKeyException {
        if (log.isDebugEnabled()) {
            StringWriter sw = new StringWriter();
            try (PrintWriter pw = new PrintWriter(sw);){
                pw.println("Testing a key:");
                pw.println(String.format("\tTesting keys with algorithm: %s", pubKey.getAlgorithm()));
                pw.println(String.format("\tprovider: %s", provider));
                pw.println(String.format("\tprivateKey: %s", privKey));
                pw.println(String.format("\tprivateKey class: %s", privKey.getClass().getName()));
                pw.println(String.format("\tpublicKey: %s", pubKey));
                pw.println(String.format("\tpublicKey class: %s", pubKey.getClass().getName()));
                pw.flush();
            }
            log.debug((Object)sw.toString());
        }
        String varArLillan = "Lillan ar borta...";
        CMSEnvelopedData cMSEnvelopedData = null;
        CMSEnvelopedDataGenerator cMSEDGenerator = new CMSEnvelopedDataGenerator();
        byte[] keyId = KeyTools.createSubjectKeyId(pubKey).getKeyIdentifier();
        cMSEDGenerator.addRecipientInfoGenerator((RecipientInfoGenerator)new JceKeyTransRecipientInfoGenerator(keyId, pubKey));
        JceCMSContentEncryptorBuilder builder = new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC).setProvider("BC");
        try {
            cMSEnvelopedData = cMSEDGenerator.generate((CMSTypedData)new CMSProcessableByteArray("Lillan ar borta...".getBytes(StandardCharsets.US_ASCII)), builder.build());
        }
        catch (CMSException e) {
            throw new InvalidKeyException(e.getMessage());
        }
        RecipientInformationStore recipients = cMSEnvelopedData.getRecipientInfos();
        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();
        JceKeyTransEnvelopedRecipient rec = new JceKeyTransEnvelopedRecipient(privKey);
        rec.setProvider(provider);
        rec.setContentProvider("BC");
        rec.setMustProduceEncodableUnwrappedKey(false);
        String decryptedString = "";
        try {
            decryptedString = new String(recipient.getContent((Recipient)rec), StandardCharsets.US_ASCII);
        }
        catch (CMSException e) {
            throw new InvalidKeyException(e.getMessage());
        }
        return "Lillan ar borta...".equals(decryptedString);
    }

    public static void printPublicKeyInfo(PublicKey publK, PrintStream ps) {
        if (publK instanceof RSAPublicKey) {
            ps.println("RSA key:");
            RSAPublicKey rsa = (RSAPublicKey)publK;
            ps.println("  modulus: " + rsa.getModulus().toString(16));
            ps.println("  public exponent: " + rsa.getPublicExponent().toString(16));
            return;
        }
        if (publK instanceof ECPublicKey) {
            ps.println("Elliptic curve key:");
            ECPublicKey ec = (ECPublicKey)publK;
            ps.println("  Named curve: " + AlgorithmTools.getKeySpecification(ec));
            ps.println("  the affine x-coordinate: " + ec.getW().getAffineX().toString(16));
            ps.println("  the affine y-coordinate: " + ec.getW().getAffineY().toString(16));
            return;
        }
        if (publK instanceof DHPublicKey) {
            ps.println("DH key:");
            DHPublicKey dh = (DHPublicKey)publK;
            ps.println("  the public value y: " + dh.getY().toString(16));
            return;
        }
        if (publK instanceof BCEdDSAPublicKey) {
            ps.println("EdDSA key:");
            String algo = publK.getAlgorithm();
            BCEdDSAPublicKey eddsa = (BCEdDSAPublicKey)publK;
            ps.println("  " + algo);
            String key = org.bouncycastle.util.encoders.Base64.toBase64String((byte[])eddsa.getEncoded());
            ps.println("  public key value " + key);
        }
    }

    public static boolean isPrivateKeyExtractable(PrivateKey privK) {
        if (privK instanceof RSAPrivateKey) {
            RSAPrivateKey rsa = (RSAPrivateKey)privK;
            BigInteger result = rsa.getPrivateExponent();
            return result != null && result.bitLength() > 0;
        }
        if (privK instanceof ECPrivateKey) {
            ECPrivateKey ec = (ECPrivateKey)privK;
            BigInteger result = ec.getS();
            return result != null && result.bitLength() > 0;
        }
        if (privK instanceof DHPrivateKey) {
            DHPrivateKey dh = (DHPrivateKey)privK;
            BigInteger result = dh.getX();
            return result != null && result.bitLength() > 0;
        }
        if (privK instanceof BCEdDSAPrivateKey) {
            BCEdDSAPrivateKey ed = (BCEdDSAPrivateKey)privK;
            byte[] result = ed.getEncoded();
            return result != null && result.length > 0;
        }
        return false;
    }

    public static void checkValidKeyLength(String keyspec) throws InvalidKeyException, InvalidAlgorithmParameterException {
        int len;
        String keyAlg = KeyTools.keyspecToKeyalg(keyspec);
        if (keyAlg.equals("RSA")) {
            len = Integer.parseInt(keyspec);
        } else if (keyAlg.equals("Ed25519")) {
            len = 255;
        } else if (keyAlg.equals("Ed448")) {
            len = 448;
        } else if (keyAlg.equals("FALCON-512")) {
            len = Integer.parseInt(keyspec.substring(6));
        } else if (keyAlg.equals("FALCON-1024")) {
            len = Integer.parseInt(keyspec.substring(6));
        } else if (keyAlg.equals("ML-KEM-512")) {
            len = Integer.parseInt(keyspec.substring(6));
        } else if (keyAlg.equals("ML-KEM-768")) {
            len = Integer.parseInt(keyspec.substring(6));
        } else if (keyAlg.equals("ML-KEM-1024")) {
            len = Integer.parseInt(keyspec.substring(6));
        } else {
            KeyPair kp = KeyTools.genKeys(keyspec, keyAlg);
            len = KeyTools.getKeyLength(kp.getPublic());
        }
        KeyTools.checkValidKeyLength(keyAlg, len);
    }

    public static void checkValidKeyLength(PublicKey pk) throws InvalidKeyException {
        String keyAlg = AlgorithmTools.getKeyAlgorithm(pk);
        int len = KeyTools.getKeyLength(pk);
        KeyTools.checkValidKeyLength(keyAlg, len);
    }

    public static void checkValidKeyLength(String keyAlg, int len) throws InvalidKeyException {
        if ("ECDSA".equals(keyAlg)) {
            if (len >= 0 && len < 224) {
                String msg = "ECDSA keys of smaller size than 224 is not allowed for a CA. Requested length was " + len;
                throw new InvalidKeyException(msg);
            }
        } else if ("RSA".equals(keyAlg) && len < 1024) {
            String msg = "RSA keys of smaller size than 1024 is not allowed for a CA. Requested length was " + len;
            throw new InvalidKeyException(msg);
        }
    }

    public static String keyspecToKeyalg(String keyspec) {
        if (StringUtils.isNumeric((String)keyspec)) {
            return "RSA";
        }
        if (keyspec.startsWith("RSA")) {
            return "RSA";
        }
        if (keyspec.equalsIgnoreCase("Ed25519")) {
            return "Ed25519";
        }
        if (keyspec.equalsIgnoreCase("Ed448")) {
            return "Ed448";
        }
        if (StringUtils.startsWithIgnoreCase((String)keyspec, (String)"FALCON-512")) {
            return "FALCON-512";
        }
        if (StringUtils.startsWithIgnoreCase((String)keyspec, (String)"FALCON-1024")) {
            return "FALCON-1024";
        }
        if (StringUtils.startsWithIgnoreCase((String)keyspec, (String)"ML-KEM-512")) {
            return "ML-KEM-512";
        }
        if (StringUtils.startsWithIgnoreCase((String)keyspec, (String)"ML-KEM-768")) {
            return "ML-KEM-768";
        }
        if (StringUtils.startsWithIgnoreCase((String)keyspec, (String)"ML-KEM-1024")) {
            return "ML-KEM-1024";
        }
        if (StringUtils.startsWithIgnoreCase((String)keyspec, (String)"ML-DSA-44")) {
            return "ML-DSA-44";
        }
        if (StringUtils.startsWithIgnoreCase((String)keyspec, (String)"ML-DSA-65")) {
            return "ML-DSA-65";
        }
        if (StringUtils.startsWithIgnoreCase((String)keyspec, (String)"ML-DSA-87")) {
            return "ML-DSA-87";
        }
        if (StringUtils.startsWithIgnoreCase((String)keyspec, (String)"SLH-DSA-SHA2-128S")) {
            return "SLH-DSA-SHA2-128S";
        }
        if (StringUtils.startsWithIgnoreCase((String)keyspec, (String)"SLH-DSA-SHAKE-128S")) {
            return "SLH-DSA-SHAKE-128S";
        }
        if (StringUtils.startsWithIgnoreCase((String)keyspec, (String)"SLH-DSA-SHA2-128F")) {
            return "SLH-DSA-SHA2-128F";
        }
        if (StringUtils.startsWithIgnoreCase((String)keyspec, (String)"SLH-DSA-SHAKE-128F")) {
            return "SLH-DSA-SHAKE-128F";
        }
        if (StringUtils.startsWithIgnoreCase((String)keyspec, (String)"SLH-DSA-SHA2-192S")) {
            return "SLH-DSA-SHA2-192S";
        }
        if (StringUtils.startsWithIgnoreCase((String)keyspec, (String)"SLH-DSA-SHAKE-192S")) {
            return "SLH-DSA-SHAKE-192S";
        }
        if (StringUtils.startsWithIgnoreCase((String)keyspec, (String)"SLH-DSA-SHA2-192F")) {
            return "SLH-DSA-SHA2-192F";
        }
        if (StringUtils.startsWithIgnoreCase((String)keyspec, (String)"SLH-DSA-SHAKE-192F")) {
            return "SLH-DSA-SHAKE-192F";
        }
        if (StringUtils.startsWithIgnoreCase((String)keyspec, (String)"SLH-DSA-SHA2-256S")) {
            return "SLH-DSA-SHA2-256S";
        }
        if (StringUtils.startsWithIgnoreCase((String)keyspec, (String)"SLH-DSA-SHAKE-256S")) {
            return "SLH-DSA-SHAKE-256S";
        }
        if (StringUtils.startsWithIgnoreCase((String)keyspec, (String)"SLH-DSA-SHA2-256F")) {
            return "SLH-DSA-SHA2-256F";
        }
        if (StringUtils.startsWithIgnoreCase((String)keyspec, (String)"SLH-DSA-SHAKE-256F")) {
            return "SLH-DSA-SHAKE-256F";
        }
        return "ECDSA";
    }

    public static String shortenKeySpec(String keyspec) {
        if (keyspec.startsWith("RSA")) {
            return keyspec.substring(3);
        }
        return keyspec;
    }

    public static PublicKey getPublicKeyFromBytes(byte[] asn1EncodedPublicKey) {
        try {
            SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance((Object)asn1EncodedPublicKey);
            AlgorithmIdentifier keyAlg = keyInfo.getAlgorithm();
            X509EncodedKeySpec xKeySpec = new X509EncodedKeySpec(new DERBitString((ASN1Encodable)keyInfo).getBytes());
            KeyFactory keyFact = KeyFactory.getInstance(keyAlg.getAlgorithm().getId(), CryptoProviderTools.getProviderNameFromAlg(keyAlg.getAlgorithm().getId()));
            return keyFact.generatePublic(xKeySpec);
        }
        catch (IOException | IllegalArgumentException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            log.debug((Object)"Unable to decode PublicKey.", (Throwable)e);
            return null;
        }
    }

    /*
     * Enabled aggressive block sorting
     * Enabled unnecessary exception pruning
     * Enabled aggressive exception aggregation
     */
    public static KeyPair getKeyPairFromPEM(String pemData) {
        try (PEMParser pemParser = new PEMParser((Reader)new StringReader(pemData));){
            Object obj = pemParser.readObject();
            if (obj instanceof PEMKeyPair) {
                PEMKeyPair pemKeyPair = (PEMKeyPair)obj;
                String alg = pemKeyPair.getPrivateKeyInfo().getPrivateKeyAlgorithm().getAlgorithm().getId();
                JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter().setProvider(CryptoProviderTools.getProviderNameFromAlg(alg));
                KeyPair keyPair = keyConverter.getKeyPair(pemKeyPair);
                return keyPair;
            }
            PrivateKeyInfo privInfo = (PrivateKeyInfo)obj;
            String alg = privInfo.getPrivateKeyAlgorithm().getAlgorithm().getId();
            JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter().setProvider(CryptoProviderTools.getProviderNameFromAlg(alg));
            PrivateKey privKey = keyConverter.getPrivateKey(privInfo);
            if (privKey instanceof EdDSAPrivateKey) {
                EdDSAPublicKey edPubKey = ((EdDSAPrivateKey)privKey).getPublicKey();
                KeyPair keyPair = new KeyPair((PublicKey)edPubKey, privKey);
                return keyPair;
            }
            if (privKey instanceof FalconPrivateKey) {
                FalconPublicKey pubKey = ((FalconPrivateKey)privKey).getPublicKey();
                KeyPair keyPair = new KeyPair((PublicKey)pubKey, privKey);
                return keyPair;
            }
            if (privKey instanceof MLKEMPrivateKey) {
                MLKEMPublicKey pubKey = ((MLKEMPrivateKey)privKey).getPublicKey();
                KeyPair keyPair = new KeyPair((PublicKey)pubKey, privKey);
                return keyPair;
            }
            if (privKey instanceof MLDSAPrivateKey) {
                MLDSAPublicKey pubKey = ((MLDSAPrivateKey)privKey).getPublicKey();
                KeyPair keyPair = new KeyPair((PublicKey)pubKey, privKey);
                return keyPair;
            }
            if (!(privKey instanceof SLHDSAPrivateKey)) throw new IllegalStateException("No known keytype for object " + privKey.getClass().getName());
            SLHDSAPublicKey pubKey = ((SLHDSAPrivateKey)privKey).getPublicKey();
            KeyPair keyPair = new KeyPair((PublicKey)pubKey, privKey);
            return keyPair;
        }
        catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] getBytesFromPEM(String pem, String beginMarker, String endMarker) {
        int start = pem.indexOf(beginMarker);
        int end = pem.indexOf(endMarker, start);
        if (start == -1 || end == -1) {
            log.debug((Object)("Could not find " + beginMarker + " and " + endMarker + " lines in PEM"));
            return null;
        }
        String base64 = pem.substring(start + beginMarker.length(), end);
        return Base64.decode(base64.getBytes(StandardCharsets.US_ASCII));
    }

    public static byte[] getBytesFromPublicKeyFile(byte[] file) throws CertificateParsingException {
        if (file.length == 0) {
            throw new CertificateParsingException("Public key file is empty");
        }
        String fileText = StandardCharsets.US_ASCII.decode(ByteBuffer.wrap(file)).toString();
        byte[] tmpBytes = KeyTools.getBytesFromPEM(fileText, "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----");
        byte[] asn1bytes = tmpBytes != null ? tmpBytes : file;
        try {
            org.bouncycastle.crypto.util.PublicKeyFactory.createKey((byte[])asn1bytes);
            return asn1bytes;
        }
        catch (IOException | IllegalArgumentException e) {
            try {
                PublicKeyFactory.createKey((byte[])asn1bytes);
                return asn1bytes;
            }
            catch (IOException | IllegalArgumentException exception) {
                throw new CertificateParsingException("File is neither a valid PEM nor DER file.", e);
            }
        }
    }

    public static byte[] getBytesFromCtLogKey(byte[] file) throws CertificateParsingException {
        try {
            return KeyTools.getBytesFromPublicKeyFile(file);
        }
        catch (CertificateParsingException originalException) {
            byte[] decoded;
            log.debug((Object)"Could not parse key as PEM or DER, trying as raw base64.", (Throwable)originalException);
            try {
                decoded = Base64.decode(file);
            }
            catch (DecoderException ignored) {
                log.debug((Object)"Public key file is not valid base64");
                throw new CertificateParsingException("Public key could not be parsed as either PEM, DER or base64.", originalException);
            }
            if (decoded == null || decoded.length == 0) {
                log.debug((Object)"Decoded base64 data of public key is empty or null");
                throw originalException;
            }
            try {
                org.bouncycastle.crypto.util.PublicKeyFactory.createKey((byte[])decoded);
                return decoded;
            }
            catch (IOException | IllegalArgumentException e) {
                String msg = "The base64 encoded data does not represent a public key.";
                log.debug((Object)"The base64 encoded data does not represent a public key.");
                throw new CertificateParsingException("The base64 encoded data does not represent a public key.", e);
            }
        }
    }

    public static String getKeyModulus(PublicKey publicKey) {
        String modulus = null;
        if (publicKey instanceof RSAPublicKey) {
            byte[] modulusBytes = ((RSAPublicKey)publicKey).getModulus().toByteArray();
            modulus = new String(Hex.encode((byte[])modulusBytes));
        } else if (publicKey instanceof ECPublicKey) {
            byte[] modulusBytesX = ((ECPublicKey)publicKey).getW().getAffineX().toByteArray();
            byte[] modulusBytesY = ((ECPublicKey)publicKey).getW().getAffineY().toByteArray();
            modulus = new String(Hex.encode((byte[])modulusBytesX)).concat(new String(Hex.encode((byte[])modulusBytesY)));
        }
        return modulus;
    }

    public static String getKeyPublicExponent(PublicKey publicKey) {
        String exponent = null;
        if (publicKey instanceof RSAPublicKey) {
            exponent = ((RSAPublicKey)publicKey).getPublicExponent().toString();
        }
        return exponent;
    }

    public static String getSha256Fingerprint(String text) {
        byte[] sha256Fingerprint = CertTools.generateSHA256Fingerprint(text.getBytes());
        return new String(Hex.encode((byte[])sha256Fingerprint));
    }

    public static String getCertificateRequestSignature(JcaPKCS10CertificationRequest certificationRequest) {
        return new String(Hex.encode((byte[])certificationRequest.getSignature()));
    }

    public static boolean isUsingExportableCryptography() {
        boolean returnValue = true;
        try {
            int keylen = Cipher.getMaxAllowedKeyLength("DES");
            if (log.isDebugEnabled()) {
                log.debug((Object)("MaxAllowedKeyLength for DES is: " + keylen));
            }
            if (keylen == Integer.MAX_VALUE) {
                returnValue = false;
            }
        }
        catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            // empty catch block
        }
        return returnValue;
    }

    private static class SignDataOperation
    implements ISignOperation {
        private final PrivateKey key;
        private final byte[] dataToBeSigned;
        private byte[] signatureBV;
        private String signatureAlgorithm;

        public SignDataOperation(PrivateKey _key, byte[] _dataToBeSigned) {
            this.key = _key;
            this.dataToBeSigned = _dataToBeSigned;
        }

        @Override
        public void taskWithSigning(String signAlgorithm, Provider provider) throws TaskWithSigningException {
            try {
                Signature signature = Signature.getInstance(signAlgorithm, provider);
                signature.initSign(this.key);
                signature.update(this.dataToBeSigned);
                this.signatureBV = signature.sign();
            }
            catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
                throw new TaskWithSigningException(String.format("Signing of data failed: %s", e.getMessage()), e);
            }
            this.signatureAlgorithm = signAlgorithm;
        }

        public byte[] getSignature() {
            return this.signatureBV;
        }

        public String getSignatureAlgorithm() {
            return this.signatureAlgorithm;
        }
    }
}

