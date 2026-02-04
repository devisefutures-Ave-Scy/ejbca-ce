/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.commons.lang.StringUtils
 *  org.apache.log4j.Logger
 *  org.bouncycastle.asn1.ASN1Set
 *  org.bouncycastle.asn1.DERSet
 *  org.bouncycastle.asn1.x500.X500Name
 *  org.bouncycastle.asn1.x9.X9ECParameters
 *  org.bouncycastle.cert.X509CertificateHolder
 *  org.bouncycastle.cert.X509v3CertificateBuilder
 *  org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
 *  org.bouncycastle.crypto.ec.CustomNamedCurves
 *  org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil
 *  org.bouncycastle.jcajce.spec.EdDSAParameterSpec
 *  org.bouncycastle.jcajce.spec.MLDSAParameterSpec
 *  org.bouncycastle.jcajce.spec.SLHDSAParameterSpec
 *  org.bouncycastle.jce.ECKeyUtil
 *  org.bouncycastle.jce.spec.ECParameterSpec
 *  org.bouncycastle.operator.BufferingContentSigner
 *  org.bouncycastle.operator.ContentSigner
 *  org.bouncycastle.operator.ContentVerifierProvider
 *  org.bouncycastle.operator.OperatorCreationException
 *  org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
 *  org.bouncycastle.pkcs.PKCS10CertificationRequest
 *  org.bouncycastle.pkcs.PKCSException
 *  org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec
 *  org.bouncycastle.pqc.jcajce.spec.LMSKeyGenParameterSpec
 */
package com.keyfactor.util.keys;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.CachingKeyStoreWrapper;
import com.keyfactor.util.keys.ISignOperation;
import com.keyfactor.util.keys.KeyCreationException;
import com.keyfactor.util.keys.KeyUtilRuntimeException;
import com.keyfactor.util.keys.SignWithWorkingAlgorithm;
import com.keyfactor.util.keys.TaskWithSigningException;
import com.keyfactor.util.keys.token.KeyGenParams;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
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
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.LMSKeyGenParameterSpec;

public class KeyStoreTools {
    private static final Logger log = Logger.getLogger(KeyStoreTools.class);
    protected final CachingKeyStoreWrapper keyStore;
    private final String providerName;

    public KeyStoreTools(CachingKeyStoreWrapper keyStore, String providerName) {
        this.keyStore = keyStore;
        this.providerName = providerName;
    }

    public String getProviderName() {
        return this.providerName;
    }

    public CachingKeyStoreWrapper getKeyStore() {
        return this.keyStore;
    }

    public void setKeyEntry(String alias, Key key, Certificate[] chain) throws KeyStoreException {
        this.getKeyStore().deleteEntry(alias);
        this.getKeyStore().setKeyEntry(alias, key, null, chain);
    }

    private void deleteAlias(String alias) throws KeyStoreException {
        this.getKeyStore().deleteEntry(alias);
    }

    public void deleteEntry(String alias) throws KeyStoreException {
        if (alias != null) {
            this.deleteAlias(alias);
            return;
        }
        Enumeration<String> e = this.getKeyStore().aliases();
        while (e.hasMoreElements()) {
            String str = e.nextElement();
            this.deleteAlias(str);
        }
    }

    public void renameEntry(String oldAlias, String newAlias) {
        try {
            this.getKeyStore().setEntry(newAlias, this.getKeyStore().getEntry(oldAlias, null), null);
        }
        catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            throw new KeyUtilRuntimeException("Renaming entry failed.", e);
        }
    }

    private X509Certificate getSelfCertificate(String myName, long validity, List<String> sigAlgs, KeyPair keyPair) throws InvalidKeyException, CertificateException {
        long currentTime = new Date().getTime();
        Date firstDate = new Date(currentTime - 86400000L);
        Date lastDate = new Date(currentTime + validity * 1000L);
        X500Name issuer = new X500Name(myName);
        BigInteger serno = BigInteger.valueOf(firstDate.getTime());
        PublicKey publicKey = keyPair.getPublic();
        if (publicKey == null) {
            throw new InvalidKeyException("Public key is null");
        }
        try {
            JcaX509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(issuer, serno, firstDate, lastDate, issuer, publicKey);
            CertificateSignOperation cso = new CertificateSignOperation(keyPair.getPrivate(), (X509v3CertificateBuilder)cb);
            String provider = this.providerName;
            if ("BC".equals(this.providerName)) {
                provider = CryptoProviderTools.getProviderNameFromAlg(sigAlgs.get(0));
            }
            SignWithWorkingAlgorithm.doSignTask(sigAlgs, provider, (ISignOperation)cso);
            X509CertificateHolder cert = cso.getResult();
            if (cert == null) {
                throw new CertificateException("Self signing of certificate failed.");
            }
            return CertTools.getCertfromByteArray(cert.getEncoded(), X509Certificate.class);
        }
        catch (TaskWithSigningException e) {
            log.error((Object)"Error creating content signer: ", (Throwable)e);
            throw new CertificateException(e);
        }
        catch (IOException e) {
            throw new CertificateException("Could not read certificate", e);
        }
        catch (NoSuchProviderException e) {
            throw new CertificateException(String.format("Provider '%s' does not exist.", this.providerName), e);
        }
    }

    private void generateEC(String ecNamedCurveBc, String keyAlias) throws InvalidAlgorithmParameterException {
        final AlgorithmParameterSpec keyParams;
        if (log.isTraceEnabled()) {
            log.trace((Object)(">generate EC: curve name " + ecNamedCurveBc + ", keyEntryName " + keyAlias));
        }
        if (StringUtils.contains((String)Security.getProvider(this.providerName).getClass().getName(), (String)"iaik")) {
            throw new InvalidAlgorithmParameterException("IAIK ECC key generation not implemented.");
        }
        if (ECUtil.getNamedCurveOid((String)ecNamedCurveBc) != null) {
            String oidOrName = AlgorithmTools.getEcKeySpecOidFromBcName(ecNamedCurveBc);
            if (log.isDebugEnabled()) {
                log.debug((Object)("keySpecification '" + ecNamedCurveBc + "' transformed into OID " + oidOrName));
            }
            keyParams = new ECGenParameterSpec(oidOrName);
        } else {
            X9ECParameters ecP;
            if (log.isDebugEnabled()) {
                log.debug((Object)("Curve did not have an OID in BC, trying to pick up Parameter spec: " + ecNamedCurveBc));
            }
            if ((ecP = CustomNamedCurves.getByName((String)ecNamedCurveBc)) == null) {
                throw new InvalidAlgorithmParameterException("Can not generate EC curve, no OID and no ECParameters found: " + ecNamedCurveBc);
            }
            keyParams = new ECParameterSpec(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
        }
        this.generateKeyPair(keyParams, keyAlias, "EC", AlgorithmTools.SIG_ALGS_ECDSA);
        if (log.isTraceEnabled()) {
            log.trace((Object)("<generate: curve name " + ecNamedCurveBc + ", keyEntryName " + keyAlias));
        }
    }

    private void generateRSA(int keySize, String keyEntryName) throws InvalidAlgorithmParameterException {
        if (log.isTraceEnabled()) {
            log.trace((Object)(">generate: keySize " + keySize + ", keyEntryName " + keyEntryName));
        }
        this.generateKeyPair(new SizeAlgorithmParameterSpec(keySize), keyEntryName, "RSA", AlgorithmTools.SIG_ALGS_RSA_NOSHA1);
        if (log.isTraceEnabled()) {
            log.trace((Object)("<generate: keySize " + keySize + ", keyEntryName " + keyEntryName));
        }
    }

    private void generateEdDSAOrPQC(String keySpec, String keyAlias) throws InvalidAlgorithmParameterException {
        List<String> sigAlgs;
        if (log.isTraceEnabled()) {
            log.trace((Object)(">generate: keySpec " + keySpec + ", keyEntryName " + keyAlias));
        }
        LMSKeyGenParameterSpec keyParams = null;
        switch (keySpec) {
            case "Ed25519": {
                sigAlgs = AlgorithmTools.SIG_ALGS_ED25519;
                break;
            }
            case "Ed448": {
                sigAlgs = AlgorithmTools.SIG_ALGS_ED448;
                break;
            }
            case "FALCON-512": {
                sigAlgs = AlgorithmTools.SIG_ALGS_FALCON512;
                break;
            }
            case "FALCON-1024": {
                sigAlgs = AlgorithmTools.SIG_ALGS_FALCON1024;
                break;
            }
            case "ML-DSA-44": {
                sigAlgs = AlgorithmTools.SIG_ALGS_MLDSA44;
                break;
            }
            case "ML-DSA-65": {
                sigAlgs = AlgorithmTools.SIG_ALGS_MLDSA65;
                break;
            }
            case "ML-DSA-87": {
                sigAlgs = AlgorithmTools.SIG_ALGS_MLDSA87;
                break;
            }
            case "SLH-DSA-SHA2-128S": {
                sigAlgs = AlgorithmTools.SIG_ALGS_SLHDSA_SHA2_128S;
                break;
            }
            case "SLH-DSA-SHAKE-128S": {
                sigAlgs = AlgorithmTools.SIG_ALGS_SLHDSA_SHAKE_128S;
                break;
            }
            case "SLH-DSA-SHA2-128F": {
                sigAlgs = AlgorithmTools.SIG_ALGS_SLHDSA_SHA2_128F;
                break;
            }
            case "SLH-DSA-SHAKE-128F": {
                sigAlgs = AlgorithmTools.SIG_ALGS_SLHDSA_SHAKE_128F;
                break;
            }
            case "SLH-DSA-SHA2-192S": {
                sigAlgs = AlgorithmTools.SIG_ALGS_SLHDSA_SHA2_192S;
                break;
            }
            case "SLH-DSA-SHAKE-192S": {
                sigAlgs = AlgorithmTools.SIG_ALGS_SLHDSA_SHAKE_192S;
                break;
            }
            case "SLH-DSA-SHA2-192F": {
                sigAlgs = AlgorithmTools.SIG_ALGS_SLHDSA_SHA2_192F;
                break;
            }
            case "SLH-DSA-SHAKE-192F": {
                sigAlgs = AlgorithmTools.SIG_ALGS_SLHDSA_SHAKE_192F;
                break;
            }
            case "SLH-DSA-SHA2-256S": {
                sigAlgs = AlgorithmTools.SIG_ALGS_SLHDSA_SHA2_256S;
                break;
            }
            case "SLH-DSA-SHAKE-256S": {
                sigAlgs = AlgorithmTools.SIG_ALGS_SLHDSA_SHAKE_256S;
                break;
            }
            case "SLH-DSA-SHA2-256F": {
                sigAlgs = AlgorithmTools.SIG_ALGS_SLHDSA_SHA2_256F;
                break;
            }
            case "SLH-DSA-SHAKE-256F": {
                sigAlgs = AlgorithmTools.SIG_ALGS_SLHDSA_SHAKE_256F;
                break;
            }
            case "LMS": {
                sigAlgs = AlgorithmTools.SIG_ALGS_LMS;
                keyParams = LMSKeyGenParameterSpec.fromNames((String)"lms-sha256-n32-h5", (String)"sha256-n32-w8");
                break;
            }
            default: {
                throw new InvalidAlgorithmParameterException("Only Ed25519, Ed448, FALCON-512, FALCON-1024, ML-DSA-44, ML-DSA-65, ML-DSA-87, SLH-DSA-SHA2-128S, SLH-DSA-SHAKE-128S, SLH-DSA-SHA2-128F, SLH-DSA-SHAKE-128F, SLH-DSA-SHA2-192S, SLH-DSA-SHAKE-192S, SLH-DSA-SHA2-192F, SLH-DSA-SHAKE-192F, SLH-DSA-SHA2-256S, SLH-DSA-SHAKE-256S, SLH-DSA-SHA2-256F, SLH-DSA-SHAKE-256F is allowed for EdDSA/PQC key generation: " + keySpec);
            }
        }
        this.generateKeyPair((AlgorithmParameterSpec)keyParams, keyAlias, keySpec, sigAlgs);
        if (log.isTraceEnabled()) {
            log.trace((Object)("<generate: keySpec " + keySpec + ", keyEntryName " + keyAlias));
        }
    }

    public void generateKeyPair(String keySpec, String keyEntryName) throws InvalidAlgorithmParameterException {
        if (keySpec.toUpperCase().startsWith("ED") || keySpec.toUpperCase().startsWith("FALCON") || keySpec.toUpperCase().startsWith("ML") || keySpec.toUpperCase().startsWith("LMS") || keySpec.toUpperCase().startsWith("SLH")) {
            this.generateEdDSAOrPQC(keySpec, keyEntryName);
        } else {
            String formatCheckedKeySpec = KeyGenParams.getKeySpecificationNumeric(keySpec);
            try {
                this.generateRSA(Integer.parseInt(formatCheckedKeySpec.trim()), keyEntryName);
            }
            catch (NumberFormatException e) {
                this.generateEC(keySpec, keyEntryName);
            }
        }
    }

    public void generateKey(String algorithm, int keysize, String keyEntryName) throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException {
        KeyGenerator generator = KeyGenerator.getInstance(algorithm, this.providerName);
        generator.init(keysize);
        SecretKey key = generator.generateKey();
        this.setKeyEntry(keyEntryName, key, null);
    }

    /*
     * Enabled force condition propagation
     * Lifted jumps to return sites
     */
    public void generateKeyPair(AlgorithmParameterSpec keyParams, String keyAlias) throws InvalidAlgorithmParameterException {
        List<String> certSignAlgorithms;
        String keyAlgorithm;
        String specName;
        if (log.isTraceEnabled()) {
            log.trace((Object)(">generate from AlgorithmParameterSpec: " + keyParams.getClass().getName()));
        }
        if ((specName = keyParams.getClass().getName()).equals(EdDSAParameterSpec.class.getName())) {
            EdDSAParameterSpec edSpec = (EdDSAParameterSpec)keyParams;
            keyAlgorithm = edSpec.getCurveName();
            certSignAlgorithms = Collections.singletonList(edSpec.getCurveName());
        } else if (specName.contains("RSA")) {
            keyAlgorithm = "RSA";
            certSignAlgorithms = AlgorithmTools.SIG_ALGS_RSA_NOSHA1;
        } else if (specName.equals(FalconParameterSpec.class.getName())) {
            if (FalconParameterSpec.falcon_512.equals(keyParams)) {
                keyAlgorithm = "FALCON-512";
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_FALCON512;
            } else {
                if (!FalconParameterSpec.falcon_1024.equals(keyParams)) throw new InvalidAlgorithmParameterException("Invalid Falcon keyspec: " + keyParams);
                keyAlgorithm = "FALCON-1024";
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_FALCON1024;
            }
        } else if (specName.equals(MLDSAParameterSpec.class.getName())) {
            if (MLDSAParameterSpec.ml_dsa_44.equals(keyParams)) {
                keyAlgorithm = "ML-DSA-44";
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_MLDSA44;
            } else if (MLDSAParameterSpec.ml_dsa_65.equals(keyParams)) {
                keyAlgorithm = "ML-DSA-65";
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_MLDSA65;
            } else {
                if (!MLDSAParameterSpec.ml_dsa_87.equals(keyParams)) throw new InvalidAlgorithmParameterException("Invalid ML-DSA keyspec: " + keyParams);
                keyAlgorithm = "ML-DSA-87";
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_MLDSA87;
            }
        } else if (specName.equals(SLHDSAParameterSpec.class.getName())) {
            if (SLHDSAParameterSpec.slh_dsa_sha2_128s.equals(keyParams)) {
                keyAlgorithm = "SLH-DSA-SHA2-128S";
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_SLHDSA_SHA2_128S;
            } else if (SLHDSAParameterSpec.slh_dsa_shake_128s.equals(keyParams)) {
                keyAlgorithm = "SLH-DSA-SHAKE-128S";
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_SLHDSA_SHAKE_128S;
            } else if (SLHDSAParameterSpec.slh_dsa_sha2_128f.equals(keyParams)) {
                keyAlgorithm = "SLH-DSA-SHA2-128F";
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_SLHDSA_SHA2_128F;
            } else if (SLHDSAParameterSpec.slh_dsa_shake_128f.equals(keyParams)) {
                keyAlgorithm = "SLH-DSA-SHAKE-128F";
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_SLHDSA_SHAKE_128F;
            } else if (SLHDSAParameterSpec.slh_dsa_sha2_192s.equals(keyParams)) {
                keyAlgorithm = "SLH-DSA-SHA2-192S";
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_SLHDSA_SHA2_192S;
            } else if (SLHDSAParameterSpec.slh_dsa_shake_192s.equals(keyParams)) {
                keyAlgorithm = "SLH-DSA-SHAKE-192S";
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_SLHDSA_SHAKE_192S;
            } else if (SLHDSAParameterSpec.slh_dsa_sha2_192f.equals(keyParams)) {
                keyAlgorithm = "SLH-DSA-SHA2-192F";
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_SLHDSA_SHA2_192F;
            } else if (SLHDSAParameterSpec.slh_dsa_shake_192f.equals(keyParams)) {
                keyAlgorithm = "SLH-DSA-SHAKE-192F";
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_SLHDSA_SHAKE_192F;
            } else if (SLHDSAParameterSpec.slh_dsa_sha2_256s.equals(keyParams)) {
                keyAlgorithm = "SLH-DSA-SHA2-256S";
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_SLHDSA_SHA2_256S;
            } else if (SLHDSAParameterSpec.slh_dsa_shake_256s.equals(keyParams)) {
                keyAlgorithm = "SLH-DSA-SHAKE-256S";
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_SLHDSA_SHAKE_256S;
            } else if (SLHDSAParameterSpec.slh_dsa_sha2_256f.equals(keyParams)) {
                keyAlgorithm = "SLH-DSA-SHA2-256F";
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_SLHDSA_SHA2_256F;
            } else {
                if (!SLHDSAParameterSpec.slh_dsa_shake_256f.equals(keyParams)) throw new InvalidAlgorithmParameterException("Invalid SLH-DSA keyspec: " + keyParams);
                keyAlgorithm = "SLH-DSA-SHAKE-256F";
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_SLHDSA_SHAKE_256F;
            }
        } else {
            keyAlgorithm = "EC";
            certSignAlgorithms = AlgorithmTools.SIG_ALGS_ECDSA;
        }
        this.generateKeyPair(keyParams, keyAlias, keyAlgorithm, certSignAlgorithms);
    }

    private void generateKeyPair(AlgorithmParameterSpec keyParams, String keyAlias, String keyAlgorithm, List<String> certSignAlgorithms) throws InvalidAlgorithmParameterException {
        KeyPairGenerator kpg;
        try {
            String provider = this.providerName;
            if ("BC".equals(this.providerName)) {
                provider = CryptoProviderTools.getProviderNameFromAlg(keyAlgorithm);
            }
            kpg = KeyPairGenerator.getInstance(keyAlgorithm, provider);
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algoritmo " + keyAlgorithm + " desconhecido...", e);
        }
        catch (NoSuchProviderException e) {
            throw new IllegalStateException(this.providerName + " was not found as a provider.", e);
        }
        try {
            if (keyParams instanceof SizeAlgorithmParameterSpec) {
                kpg.initialize(((SizeAlgorithmParameterSpec)keyParams).keySize);
            } else if (keyParams != null || keyAlgorithm.startsWith("EC")) {
                kpg.initialize(keyParams);
            }
        }
        catch (InvalidAlgorithmParameterException e) {
            log.debug((Object)("Algorithm parameters not supported: " + e.getMessage()));
            throw e;
        }
        for (int bar = 0; bar < 3; ++bar) {
            try {
                log.debug((Object)"generating...");
                KeyPair keyPair = kpg.generateKeyPair();
                int randomInt = ThreadLocalRandom.current().nextInt(1000000, 10000000);
                X509Certificate selfSignedCert = this.getSelfCertificate("CN=Dummy certificate created by a CESeCore application " + randomInt, 946080000L, certSignAlgorithms, keyPair);
                Certificate[] chain = new X509Certificate[]{selfSignedCert};
                if (log.isDebugEnabled()) {
                    log.debug((Object)("Creating certificate with entry " + keyAlias + "."));
                }
                this.setKeyEntry(keyAlias, keyPair.getPrivate(), chain);
                break;
            }
            catch (KeyStoreException e) {
                if (bar < 3) {
                    log.info((Object)("Failed to generate or store new key, will try 3 times. This was try: " + bar), (Throwable)e);
                    continue;
                }
                throw new KeyCreationException("Signing failed.", e);
            }
            catch (CertificateException e) {
                throw new KeyCreationException("Can't create keystore because dummy certificate chain creation failed.", e);
            }
            catch (InvalidKeyException e) {
                throw new KeyCreationException("Dummy certificate chain was created with an invalid key", e);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace((Object)("<generate from AlgorithmParameterSpec: " + (keyParams != null ? keyParams.getClass().getName() : "null")));
        }
    }

    public void generateCertReq(String alias, String sDN, boolean explicitEccParameters) {
        try {
            PublicKey publicKey = this.getCertificate(alias).getPublicKey();
            if (log.isDebugEnabled()) {
                log.debug((Object)("alias: " + alias + " SHA1 of public key: " + CertTools.getFingerprintAsString(publicKey.getEncoded())));
            }
            List<String> sigAlg = AlgorithmTools.getSignatureAlgorithms(publicKey);
            SignCsrOperation operation = new SignCsrOperation(alias, sDN, explicitEccParameters, publicKey);
            SignWithWorkingAlgorithm.doSignTask(sigAlg, this.providerName, (ISignOperation)operation);
            PKCS10CertificationRequest certReq = operation.getResult();
            ContentVerifierProvider verifier = CertTools.genContentVerifierProvider(publicKey);
            if (!certReq.isSignatureValid(verifier)) {
                String msg = "Certificate request is not verifying.";
                throw new KeyUtilRuntimeException("Certificate request is not verifying.");
            }
            String filename = alias + ".pem";
            try (FileOutputStream os = new FileOutputStream(filename);){
                ((OutputStream)os).write(CertTools.getPEMFromCertificateRequest(certReq.getEncoded()));
            }
            log.info((Object)("Wrote csr to file: " + filename));
        }
        catch (TaskWithSigningException | IOException | KeyStoreException | NoSuchProviderException | OperatorCreationException | PKCSException e) {
            throw new KeyUtilRuntimeException("Failed to generate a certificate request.", (Exception)e);
        }
    }

    public void installCertificate(String fileName) {
        try (FileInputStream is = new FileInputStream(fileName);){
            Certificate[] chain = CertTools.getCertsFromPEM(is, X509Certificate.class).toArray(new X509Certificate[0]);
            PublicKey importPublicKey = chain[0].getPublicKey();
            String importKeyHash = CertTools.getFingerprintAsString(importPublicKey.getEncoded());
            Enumeration<String> eAlias = this.getKeyStore().aliases();
            boolean notFound = true;
            while (eAlias.hasMoreElements() && notFound) {
                String alias = eAlias.nextElement();
                PublicKey hsmPublicKey = this.getCertificate(alias).getPublicKey();
                if (log.isDebugEnabled()) {
                    log.debug((Object)("alias: " + alias + " SHA1 of public hsm key: " + CertTools.getFingerprintAsString(hsmPublicKey.getEncoded()) + " SHA1 of first public key in chain: " + importKeyHash + (String)(chain.length == 1 ? "" : "SHA1 of last public key in chain: " + CertTools.getFingerprintAsString(chain[chain.length - 1].getPublicKey().getEncoded()))));
                }
                if (!hsmPublicKey.equals(importPublicKey)) continue;
                log.info((Object)("Found a matching public key for alias \"" + alias + "\"."));
                this.getKeyStore().setKeyEntry(alias, this.getPrivateKey(alias), null, chain);
                notFound = false;
            }
            if (notFound) {
                String msg = "Key with public key hash " + importKeyHash + " not on token.";
                throw new KeyUtilRuntimeException(msg);
            }
        }
        catch (IOException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | CertificateParsingException e) {
            throw new KeyUtilRuntimeException("Failed to install cert chain into keystore.", e);
        }
    }

    public void installTrustedRoot(String fileName) {
        try (FileInputStream is = new FileInputStream(fileName);){
            List<Certificate> chain = CertTools.getCertsFromPEM(is, Certificate.class);
            if (chain.size() < 1) {
                throw new KeyUtilRuntimeException("No certificate in file");
            }
            this.getKeyStore().setCertificateEntry("trusted", chain.get(chain.size() - 1));
        }
        catch (IOException | KeyStoreException | CertificateParsingException e) {
            throw new KeyUtilRuntimeException("Failing to install trusted certificate.", e);
        }
    }

    private PrivateKey getPrivateKey(String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        PrivateKey key = (PrivateKey)this.getKey(alias);
        if (key == null) {
            String msg = "Key alias '" + alias + "' not found in keystore.";
            log.info((Object)msg);
        }
        return key;
    }

    private Key getKey(String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        return this.getKeyStore().getKey(alias, null);
    }

    private X509Certificate getCertificate(String alias) throws KeyStoreException {
        X509Certificate cert = (X509Certificate)this.keyStore.getCertificate(alias);
        if (cert == null) {
            String msg = "Certificate alias '" + alias + "' not found in keystore.";
            log.info((Object)msg);
        }
        return cert;
    }

    /**
     * Encodes a Keystore to a byte array.
     * @param keyStore the keystore.
     * @param password the password.
     * @return the keystore encoded as byte array.
     */
    public static byte[] getAsByteArray(final KeyStore keyStore, final String password) {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            keyStore.store(outputStream, password.toCharArray());
            return outputStream.toByteArray();
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            log.error(e); //should never happen if keyStore is valid object
        }
        return null;
    }
    
    private static class CertificateSignOperation
    implements ISignOperation {
        private final PrivateKey privateKey;
        private final X509v3CertificateBuilder certificateBuilder;
        private X509CertificateHolder result;

        public CertificateSignOperation(PrivateKey pk, X509v3CertificateBuilder cb) {
            this.privateKey = pk;
            this.certificateBuilder = cb;
        }

        @Override
        public void taskWithSigning(String sigAlg, Provider provider) throws TaskWithSigningException {
            BufferingContentSigner signer;
            log.debug((Object)("Keystore signing algorithm " + sigAlg));
            try {
                signer = new BufferingContentSigner(new JcaContentSignerBuilder(sigAlg).setProvider(provider.getName()).build(this.privateKey), 20480);
            }
            catch (OperatorCreationException e) {
                throw new TaskWithSigningException(String.format("Signing certificate failed: %s", e.getMessage()), (Exception)((Object)e));
            }
            this.result = this.certificateBuilder.build((ContentSigner)signer);
        }

        public X509CertificateHolder getResult() {
            return this.result;
        }
    }

    private static class SizeAlgorithmParameterSpec
    implements AlgorithmParameterSpec {
        final int keySize;

        public SizeAlgorithmParameterSpec(int keySize) {
            this.keySize = keySize;
        }
    }

    private class SignCsrOperation
    implements ISignOperation {
        private final String alias;
        private final String sDN;
        private final boolean explicitEccParameters;
        private final PublicKey publicKeyTmp;
        private PKCS10CertificationRequest certReq;

        public SignCsrOperation(String _alias, String _sDN, boolean _explicitEccParameters, PublicKey publicKey) {
            this.alias = _alias;
            this.sDN = _sDN;
            this.explicitEccParameters = _explicitEccParameters;
            this.certReq = null;
            this.publicKeyTmp = publicKey;
        }

        private void signCSR(String signAlgorithm, Provider provider) throws NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException, KeyStoreException, OperatorCreationException, TaskWithSigningException {
            PublicKey publicKey;
            if (log.isDebugEnabled()) {
                log.debug((Object)String.format("alias: %s SHA1 of public key: %s", this.alias, CertTools.getFingerprintAsString(this.publicKeyTmp.getEncoded())));
            }
            if (signAlgorithm.contains("ECDSA") && this.explicitEccParameters) {
                log.info((Object)"Using explicit parameter encoding for ECC key.");
                publicKey = ECKeyUtil.publicToExplicitParameters((PublicKey)this.publicKeyTmp, (String)"BC");
            } else {
                log.info((Object)"Using named curve parameter encoding for ECC key.");
                publicKey = this.publicKeyTmp;
            }
            PrivateKey privateKey = KeyStoreTools.this.getPrivateKey(this.alias);
            X500Name sDNName = this.sDN != null ? new X500Name(this.sDN) : new X500Name("CN=" + this.alias);
            this.certReq = CertTools.genPKCS10CertificationRequest(signAlgorithm, sDNName, publicKey, (ASN1Set)new DERSet(), privateKey, provider.getName());
            if (this.certReq == null) {
                throw new TaskWithSigningException("Not possible to sign CSR.");
            }
        }

        @Override
        public void taskWithSigning(String signAlgorithm, Provider provider) throws TaskWithSigningException {
            try {
                this.signCSR(signAlgorithm, provider);
            }
            catch (KeyStoreException | NoSuchAlgorithmException | NoSuchProviderException | UnrecoverableKeyException | OperatorCreationException e) {
                throw new TaskWithSigningException(String.format("Not possible to sign CSR: %s", e.getMessage()), (Exception)e);
            }
        }

        public PKCS10CertificationRequest getResult() {
            return this.certReq;
        }
    }
}

