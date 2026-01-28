/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.log4j.Logger
 *  org.bouncycastle.asn1.ASN1Encodable
 *  org.bouncycastle.asn1.ASN1EncodableVector
 *  org.bouncycastle.asn1.ASN1ObjectIdentifier
 *  org.bouncycastle.asn1.DERGeneralizedTime
 *  org.bouncycastle.asn1.DERSequence
 *  org.bouncycastle.asn1.DERTaggedObject
 *  org.bouncycastle.asn1.x509.AuthorityKeyIdentifier
 *  org.bouncycastle.asn1.x509.BasicConstraints
 *  org.bouncycastle.asn1.x509.Extension
 *  org.bouncycastle.asn1.x509.PolicyInformation
 *  org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo
 *  org.bouncycastle.asn1.x509.SubjectKeyIdentifier
 *  org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
 *  org.bouncycastle.cert.CertIOException
 *  org.bouncycastle.cert.X509CertificateHolder
 *  org.bouncycastle.cert.X509v3CertificateBuilder
 *  org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
 *  org.bouncycastle.jce.X509KeyUsage
 *  org.bouncycastle.operator.BufferingContentSigner
 *  org.bouncycastle.operator.ContentSigner
 *  org.bouncycastle.operator.DigestCalculator
 *  org.bouncycastle.operator.OperatorCreationException
 *  org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
 */
package com.keyfactor.util.certificate;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.RandomHelper;
import com.keyfactor.util.SHA1DigestCalculator;
import com.keyfactor.util.certificate.DnComponents;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public final class SimpleCertGenerator {
    private static final Logger log = Logger.getLogger(SimpleCertGenerator.class);
    private static final String DEFAULT_TESTCERT_DN = "CN=Test,O=Test,C=SE";
    private static final int DEFAULT_TESTCERT_VALIDITY = 14600;
    private String subjectDn;
    private String issuerDn;
    private boolean issuerDnSet = false;
    private Date firstDate;
    private Date lastDate;
    private int validityDays = 1;
    private String policyId = null;
    private PrivateKey issuerPrivKey;
    private PrivateKey issuerAltPrivKey;
    private PublicKey entityPubKey;
    private PublicKey entityAltPubKey;
    private String sigAlg;
    private String altSigAlg;
    private boolean isCa = false;
    private int keyUsage = -1;
    private Date privateKeyNotBefore;
    private Date privateKeyNotAfter;
    private String provider;
    private boolean ldapOrder;
    private List<Extension> additionalExtensions;

    public SimpleCertGenerator() {
    }

    private SimpleCertGenerator(boolean isCa, String subjectDn, String issuerDn, int validityDays) {
        this.isCa = isCa;
        this.subjectDn = subjectDn;
        this.issuerDn = issuerDn;
        this.issuerDnSet = true;
        this.validityDays = validityDays;
    }

    public static SimpleCertGenerator forTESTCaCert() {
        return new SimpleCertGenerator(true, DEFAULT_TESTCERT_DN, DEFAULT_TESTCERT_DN, 14600);
    }

    public static SimpleCertGenerator forTESTLeafCert() {
        return new SimpleCertGenerator(false, DEFAULT_TESTCERT_DN, DEFAULT_TESTCERT_DN, 14600);
    }

    public String getSubjectDn() {
        return this.subjectDn;
    }

    public SimpleCertGenerator setSubjectDn(String subjectDn) {
        this.subjectDn = subjectDn;
        return this;
    }

    public String getIssuerDn() {
        return this.issuerDn;
    }

    public SimpleCertGenerator setIssuerDn(String issuerDn) {
        this.issuerDn = issuerDn;
        this.issuerDnSet = true;
        return this;
    }

    public Date getFirstDate() {
        return this.firstDate;
    }

    public SimpleCertGenerator setFirstDate(Date firstDate) {
        this.firstDate = firstDate;
        return this;
    }

    public Date getLastDate() {
        return this.lastDate;
    }

    public SimpleCertGenerator setLastDate(Date lastDate) {
        this.lastDate = lastDate;
        return this;
    }

    public int getValidityDays() {
        return this.validityDays;
    }

    public SimpleCertGenerator setValidityDays(int validityDays) {
        this.validityDays = validityDays;
        return this;
    }

    public String getPolicyId() {
        return this.policyId;
    }

    public SimpleCertGenerator setPolicyId(String policyId) {
        this.policyId = policyId;
        return this;
    }

    public PrivateKey getIssuerPrivKey() {
        return this.issuerPrivKey;
    }

    public SimpleCertGenerator setIssuerPrivKey(PrivateKey issuerPrivKey) {
        this.issuerPrivKey = issuerPrivKey;
        return this;
    }

    public PrivateKey getIssuerAltPrivKey() {
        return this.issuerAltPrivKey;
    }

    public SimpleCertGenerator setIssuerAltPrivKey(PrivateKey issuerAltPrivKey) {
        this.issuerAltPrivKey = issuerAltPrivKey;
        return this;
    }

    public PublicKey getEntityPubKey() {
        return this.entityPubKey;
    }

    public SimpleCertGenerator setEntityPubKey(PublicKey entityPubKey) {
        this.entityPubKey = entityPubKey;
        return this;
    }

    public PublicKey getEntityAltPubKey() {
        return this.entityAltPubKey;
    }

    public SimpleCertGenerator setEntityAltPubKey(PublicKey entityAltPubKey) {
        this.entityAltPubKey = entityAltPubKey;
        return this;
    }

    public SimpleCertGenerator setSelfSignKeyPair(KeyPair keyPair) {
        this.setEntityPubKey(keyPair.getPublic());
        this.setIssuerPrivKey(keyPair.getPrivate());
        return this;
    }

    public SimpleCertGenerator setSelfSignAltKeyPair(KeyPair altKeyPair) {
        this.setEntityAltPubKey(altKeyPair.getPublic());
        this.setIssuerAltPrivKey(altKeyPair.getPrivate());
        return this;
    }

    public String getSignatureAlgorithm() {
        return this.sigAlg;
    }

    public SimpleCertGenerator setSignatureAlgorithm(String sigAlg) {
        this.sigAlg = sigAlg;
        return this;
    }

    public String getAltSignatureAlgorithm() {
        return this.altSigAlg;
    }

    public SimpleCertGenerator setAltSignatureAlgorithm(String altSigAlg) {
        this.altSigAlg = altSigAlg;
        return this;
    }

    public boolean isCa() {
        return this.isCa;
    }

    public SimpleCertGenerator setCa(boolean isCA) {
        this.isCa = isCA;
        return this;
    }

    public int getKeyUsage() {
        return this.keyUsage;
    }

    public SimpleCertGenerator setKeyUsage(int keyUsage) {
        this.keyUsage = keyUsage;
        return this;
    }

    public Date getPrivateKeyNotBefore() {
        return this.privateKeyNotBefore;
    }

    public SimpleCertGenerator setPrivateKeyNotBefore(Date privateKeyNotBefore) {
        this.privateKeyNotBefore = privateKeyNotBefore;
        return this;
    }

    public Date getPrivateKeyNotAfter() {
        return this.privateKeyNotAfter;
    }

    public SimpleCertGenerator setPrivateKeyNotAfter(Date privateKeyNotAfter) {
        this.privateKeyNotAfter = privateKeyNotAfter;
        return this;
    }

    public String getProvider() {
        return this.provider;
    }

    public SimpleCertGenerator setProvider(String provider) {
        this.provider = provider;
        return this;
    }

    public boolean isLdapOrder() {
        return this.ldapOrder;
    }

    public SimpleCertGenerator setLdapOrder(boolean ldapOrder) {
        this.ldapOrder = ldapOrder;
        return this;
    }

    public List<Extension> getAdditionalExtensions() {
        return this.additionalExtensions;
    }

    public SimpleCertGenerator setAdditionalExtensions(List<Extension> additionalExtensions) {
        this.additionalExtensions = additionalExtensions;
        return this;
    }

    private void setDefaults() {
        Objects.requireNonNull(this.issuerPrivKey, "issuerPrivKey must be set");
        Objects.requireNonNull(this.entityPubKey, "entityPubKey must be set");
        Objects.requireNonNull(this.sigAlg, "Signature algorithm must be set");
        if (this.issuerAltPrivKey != null || this.entityAltPubKey != null || this.altSigAlg != null) {
            Objects.requireNonNull(this.issuerAltPrivKey, "For hybrid certificates, issuerAltPrivKey must be set");
            Objects.requireNonNull(this.entityAltPubKey, "For hybrid certificates, entityAltPubKey must be set");
            Objects.requireNonNull(this.altSigAlg, "For hybrid certificates, alternative signature algorithm must be set");
        }
        if (!this.issuerDnSet) {
            this.issuerDn = this.subjectDn;
        }
        if (this.firstDate == null) {
            this.firstDate = new Date();
            this.firstDate.setTime(this.firstDate.getTime() - 600000L);
        }
        if (this.lastDate == null) {
            this.lastDate = new Date();
            this.lastDate.setTime(this.lastDate.getTime() + (long)(this.validityDays * 86400000));
        }
        if (this.keyUsage == -1) {
            this.keyUsage = this.isCa ? 6 : 0;
        }
        if (this.provider == null) {
            this.provider = CryptoProviderTools.getProviderNameFromAlg(this.sigAlg);
        }
    }

    public X509Certificate generateCertificate() throws CertificateParsingException, OperatorCreationException, CertIOException {
        X509Certificate selfcert;
        this.setDefaults();
        PublicKey publicKey = null;
        if (this.entityPubKey instanceof RSAPublicKey) {
            RSAPublicKey rsapk = (RSAPublicKey)this.entityPubKey;
            RSAPublicKeySpec rSAPublicKeySpec = new RSAPublicKeySpec(rsapk.getModulus(), rsapk.getPublicExponent());
            try {
                publicKey = KeyFactory.getInstance("RSA").generatePublic(rSAPublicKeySpec);
            }
            catch (InvalidKeySpecException e) {
                log.error((Object)"Error creating RSAPublicKey from spec: ", (Throwable)e);
                publicKey = this.entityPubKey;
            }
            catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("RSA was not a known algorithm", e);
            }
        } else if (this.entityPubKey instanceof ECPublicKey) {
            ECPublicKey ecpk = (ECPublicKey)this.entityPubKey;
            try {
                ECPublicKeySpec ecspec = new ECPublicKeySpec(ecpk.getW(), ecpk.getParams());
                try {
                    publicKey = KeyFactory.getInstance("EC").generatePublic(ecspec);
                }
                catch (NoSuchAlgorithmException e) {
                    throw new IllegalStateException("EC was not a known algorithm", e);
                }
            }
            catch (InvalidKeySpecException e) {
                log.error((Object)"Error creating ECPublicKey from spec: ", (Throwable)e);
                publicKey = this.entityPubKey;
            }
        } else {
            log.debug((Object)("Not converting key of class. " + this.entityPubKey.getClass().getName()));
            publicKey = this.entityPubKey;
        }
        byte[] serno = new byte[16];
        SecureRandom random = RandomHelper.getInstance("BCSP800HYBRID");
        random.nextBytes(serno);
        SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance((Object)publicKey.getEncoded());
        X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(DnComponents.stringToBcX500Name(this.issuerDn, this.ldapOrder), new BigInteger(serno).abs(), this.firstDate, this.lastDate, DnComponents.stringToBcX500Name(this.subjectDn, this.ldapOrder), pkinfo);
        this.addExtensions(publicKey, certbuilder);
        X509CertificateHolder certHolder = SimpleCertGenerator.signCert(certbuilder, this.issuerPrivKey, this.issuerAltPrivKey, this.sigAlg, this.altSigAlg, this.provider);
        try {
            selfcert = CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);
        }
        catch (IOException e) {
            throw new IllegalStateException("Unexpected IOException was caught.", e);
        }
        return selfcert;
    }

    private void addExtensions(PublicKey publicKey, X509v3CertificateBuilder certbuilder) throws CertIOException {
        BasicConstraints bc = new BasicConstraints(this.isCa);
        certbuilder.addExtension(Extension.basicConstraints, true, (ASN1Encodable)bc);
        if (this.isCa || this.keyUsage != 0) {
            X509KeyUsage ku = new X509KeyUsage(this.keyUsage);
            certbuilder.addExtension(Extension.keyUsage, true, (ASN1Encodable)ku);
        }
        if (this.privateKeyNotBefore != null || this.privateKeyNotAfter != null) {
            ASN1EncodableVector v = new ASN1EncodableVector();
            if (this.privateKeyNotBefore != null) {
                v.add((ASN1Encodable)new DERTaggedObject(false, 0, (ASN1Encodable)new DERGeneralizedTime(this.privateKeyNotBefore)));
            }
            if (this.privateKeyNotAfter != null) {
                v.add((ASN1Encodable)new DERTaggedObject(false, 1, (ASN1Encodable)new DERGeneralizedTime(this.privateKeyNotAfter)));
            }
            certbuilder.addExtension(Extension.privateKeyUsagePeriod, false, (ASN1Encodable)new DERSequence(v));
        }
        try {
            if (this.isCa) {
                JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils((DigestCalculator)SHA1DigestCalculator.buildSha1Instance());
                SubjectKeyIdentifier ski = extensionUtils.createSubjectKeyIdentifier(publicKey);
                AuthorityKeyIdentifier aki = extensionUtils.createAuthorityKeyIdentifier(publicKey);
                certbuilder.addExtension(Extension.subjectKeyIdentifier, false, (ASN1Encodable)ski);
                certbuilder.addExtension(Extension.authorityKeyIdentifier, false, (ASN1Encodable)aki);
            }
        }
        catch (IOException extensionUtils) {
            // empty catch block
        }
        if (this.policyId != null) {
            PolicyInformation pi = new PolicyInformation(new ASN1ObjectIdentifier(this.policyId));
            DERSequence seq = new DERSequence((ASN1Encodable)pi);
            certbuilder.addExtension(Extension.certificatePolicies, false, (ASN1Encodable)seq);
        }
        if (this.additionalExtensions != null) {
            for (Extension extension : this.additionalExtensions) {
                certbuilder.addExtension(extension.getExtnId(), extension.isCritical(), extension.getParsedValue());
            }
        }
        try {
            if (this.entityAltPubKey != null) {
                certbuilder.addExtension(Extension.subjectAltPublicKeyInfo, false, (ASN1Encodable)SubjectAltPublicKeyInfo.getInstance((Object)this.entityAltPubKey.getEncoded()));
            }
        }
        catch (CertIOException e) {
            throw new IllegalStateException("Could not as alternative key extension to certificate builder.", e);
        }
    }

    private static X509CertificateHolder signCert(X509v3CertificateBuilder certbuilder, PrivateKey issuerPrivKey, PrivateKey altIssuerPrivKey, String sigAlg, String altSigAlg, String requestedProvider) throws OperatorCreationException {
        X509CertificateHolder certHolder;
        String provider = requestedProvider;
        if (provider == null || "BC".equals(provider)) {
            provider = CryptoProviderTools.getProviderNameFromAlg(sigAlg);
        }
        BufferingContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder(sigAlg).setProvider(provider).build(issuerPrivKey), 20480);
        if (altIssuerPrivKey == null) {
            certHolder = certbuilder.build((ContentSigner)signer);
        } else {
            String altProvider = CryptoProviderTools.getProviderNameFromAlg(altSigAlg);
            BufferingContentSigner altSigner = new BufferingContentSigner(new JcaContentSignerBuilder(altSigAlg).setProvider(altProvider).build(altIssuerPrivKey), 2048);
            certHolder = certbuilder.build((ContentSigner)signer, false, (ContentSigner)altSigner);
        }
        return certHolder;
    }
}

