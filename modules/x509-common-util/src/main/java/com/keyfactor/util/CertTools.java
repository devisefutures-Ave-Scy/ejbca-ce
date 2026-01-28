/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.commons.codec.binary.Base64
 *  org.apache.commons.lang.CharUtils
 *  org.apache.commons.lang.StringUtils
 *  org.apache.commons.lang.math.NumberUtils
 *  org.apache.log4j.Level
 *  org.apache.log4j.Logger
 *  org.apache.log4j.Priority
 *  org.bouncycastle.asn1.ASN1BitString
 *  org.bouncycastle.asn1.ASN1Encodable
 *  org.bouncycastle.asn1.ASN1IA5String
 *  org.bouncycastle.asn1.ASN1ObjectIdentifier
 *  org.bouncycastle.asn1.ASN1OctetString
 *  org.bouncycastle.asn1.ASN1Primitive
 *  org.bouncycastle.asn1.ASN1Sequence
 *  org.bouncycastle.asn1.ASN1Set
 *  org.bouncycastle.asn1.ASN1TaggedObject
 *  org.bouncycastle.asn1.DERBitString
 *  org.bouncycastle.asn1.DEROctetString
 *  org.bouncycastle.asn1.cms.ContentInfo
 *  org.bouncycastle.asn1.edec.EdECObjectIdentifiers
 *  org.bouncycastle.asn1.pkcs.Attribute
 *  org.bouncycastle.asn1.pkcs.CertificationRequest
 *  org.bouncycastle.asn1.pkcs.CertificationRequestInfo
 *  org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
 *  org.bouncycastle.asn1.pkcs.RSASSAPSSparams
 *  org.bouncycastle.asn1.x500.AttributeTypeAndValue
 *  org.bouncycastle.asn1.x500.RDN
 *  org.bouncycastle.asn1.x500.X500Name
 *  org.bouncycastle.asn1.x500.X500NameBuilder
 *  org.bouncycastle.asn1.x500.X500NameStyle
 *  org.bouncycastle.asn1.x500.style.IETFUtils
 *  org.bouncycastle.asn1.x509.AccessDescription
 *  org.bouncycastle.asn1.x509.AuthorityInformationAccess
 *  org.bouncycastle.asn1.x509.AuthorityKeyIdentifier
 *  org.bouncycastle.asn1.x509.DistributionPointName
 *  org.bouncycastle.asn1.x509.Extension
 *  org.bouncycastle.asn1.x509.Extensions
 *  org.bouncycastle.asn1.x509.GeneralName
 *  org.bouncycastle.asn1.x509.GeneralNames
 *  org.bouncycastle.asn1.x509.IssuingDistributionPoint
 *  org.bouncycastle.asn1.x509.KeyPurposeId
 *  org.bouncycastle.asn1.x509.PolicyInformation
 *  org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod
 *  org.bouncycastle.asn1.x509.SubjectKeyIdentifier
 *  org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
 *  org.bouncycastle.asn1.x509.X509ObjectIdentifiers
 *  org.bouncycastle.asn1.x9.X9ObjectIdentifiers
 *  org.bouncycastle.cert.CertIOException
 *  org.bouncycastle.cert.X509CRLHolder
 *  org.bouncycastle.cert.X509CertificateHolder
 *  org.bouncycastle.cert.jcajce.JcaX509CRLConverter
 *  org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
 *  org.bouncycastle.cert.jcajce.JcaX509CertificateHolder
 *  org.bouncycastle.cms.CMSAbsentContent
 *  org.bouncycastle.cms.CMSException
 *  org.bouncycastle.cms.CMSSignedData
 *  org.bouncycastle.cms.CMSSignedDataGenerator
 *  org.bouncycastle.cms.CMSTypedData
 *  org.bouncycastle.jcajce.util.MessageDigestUtils
 *  org.bouncycastle.openssl.PEMParser
 *  org.bouncycastle.operator.BufferingContentSigner
 *  org.bouncycastle.operator.ContentVerifierProvider
 *  org.bouncycastle.operator.OperatorCreationException
 *  org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
 *  org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
 *  org.bouncycastle.pkcs.PKCS10CertificationRequest
 *  org.bouncycastle.util.CollectionStore
 *  org.bouncycastle.util.Store
 *  org.bouncycastle.util.encoders.DecoderException
 *  org.bouncycastle.util.encoders.Hex
 */
package com.keyfactor.util;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CeSecoreNameStyle;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.FileTools;
import com.keyfactor.util.SecurityFilterInputStream;
import com.keyfactor.util.certificate.CertificateImplementationRegistry;
import com.keyfactor.util.certificate.CertificateWrapper;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.certificate.SimpleCertGenerator;
import com.keyfactor.util.keys.KeyTools;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.Reader;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.commons.lang.CharUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.Priority;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;

public abstract class CertTools {
    private static final Logger log = Logger.getLogger(CertTools.class);
    @Deprecated
    public static final String EMAIL = "rfc822name";
    @Deprecated
    public static final String EMAIL1 = "email";
    @Deprecated
    public static final String EMAIL2 = "EmailAddress";
    @Deprecated
    public static final String EMAIL3 = "E";
    @Deprecated
    public static final String DNS = "dNSName";
    @Deprecated
    public static final String URI = "UNIFORMRESOURCEIDENTIFIER";
    @Deprecated
    public static final String URI1 = "URI";
    @Deprecated
    public static final String URI2 = "uniformResourceId";
    @Deprecated
    public static final String IPADDR = "iPAddress";
    @Deprecated
    public static final String DIRECTORYNAME = "DIRECTORYNAME";
    public static final String REGISTEREDID = "registeredID";
    @Deprecated
    public static final String XMPPADDR = "XMPPADDR";
    @Deprecated
    public static final String SRVNAME = "srvName";
    @Deprecated
    public static final String FASCN = "fascN";
    @Deprecated
    public static final String KRB5PRINCIPAL = "krb5principal";
    @Deprecated
    public static final String KRB5PRINCIPAL_OBJECTID = "1.3.6.1.5.2.2";
    @Deprecated
    public static final String UPN = "upn";
    @Deprecated
    public static final String UPN_OBJECTID = "1.3.6.1.4.1.311.20.2.3";
    @Deprecated
    public static final String XMPPADDR_OBJECTID = "1.3.6.1.5.5.7.8.5";
    @Deprecated
    public static final String SRVNAME_OBJECTID = "1.3.6.1.5.5.7.8.7";
    @Deprecated
    public static final String PERMANENTIDENTIFIER = "permanentIdentifier";
    @Deprecated
    public static final String PERMANENTIDENTIFIER_OBJECTID = "1.3.6.1.5.5.7.8.3";
    @Deprecated
    public static final String PERMANENTIDENTIFIER_SEP = "/";
    @Deprecated
    public static final String FASCN_OBJECTID = "2.16.840.1.101.3.6.6";
    public static final String GUID = "guid";
    @Deprecated
    public static final String GUID_OBJECTID = "1.3.6.1.4.1.311.25.1";
    public static final String EFS_OBJECTID = "1.3.6.1.4.1.311.10.3.4";
    public static final String EFSR_OBJECTID = "1.3.6.1.4.1.311.10.3.4.1";
    public static final String MS_DOCUMENT_SIGNING_OBJECTID = "1.3.6.1.4.1.311.10.3.12";
    public static final String PRECERT_POISON_EXTENSION_OID = "1.3.6.1.4.1.11129.2.4.3";
    public static final String id_pkix = "1.3.6.1.5.5.7";
    public static final String id_kp = "1.3.6.1.5.5.7.3";
    public static final String id_pda = "1.3.6.1.5.5.7.9";
    public static final String id_pda_dateOfBirth = "1.3.6.1.5.5.7.9.1";
    public static final String id_pda_placeOfBirth = "1.3.6.1.5.5.7.9.2";
    public static final String id_pda_gender = "1.3.6.1.5.5.7.9.3";
    public static final String id_pda_countryOfCitizenship = "1.3.6.1.5.5.7.9.4";
    public static final String id_pda_countryOfResidence = "1.3.6.1.5.5.7.9.5";
    public static final String OID_MSTEMPLATE = "1.3.6.1.4.1.311.20.2";
    public static final String OID_MS_SZ_OID_NTDS_CA_SEC_EXT = "1.3.6.1.4.1.311.25.2";
    public static final String OID_VALIDITY_ASSURED_SHORT_TERM = "0.4.0.194121.2.1";
    public static final String Intel_amt = "2.16.840.1.113741.1.2.3";
    public static final String id_ct_redacted_domains = "1.3.6.1.4.1.11129.2.4.6";
    public static final String BEGIN_CERTIFICATE_REQUEST = "-----BEGIN CERTIFICATE REQUEST-----";
    public static final String END_CERTIFICATE_REQUEST = "-----END CERTIFICATE REQUEST-----";
    public static final String BEGIN_KEYTOOL_CERTIFICATE_REQUEST = "-----BEGIN NEW CERTIFICATE REQUEST-----";
    public static final String END_KEYTOOL_CERTIFICATE_REQUEST = "-----END NEW CERTIFICATE REQUEST-----";
    public static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERTIFICATE = "-----END CERTIFICATE-----";
    public static final String BEGIN_CERTIFICATE_WITH_NL = "-----BEGIN CERTIFICATE-----\n";
    public static final String END_CERTIFICATE_WITH_NL = "\n-----END CERTIFICATE-----\n";
    public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
    public static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
    public static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    public static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
    public static final String BEGIN_X509_CRL_KEY = "-----BEGIN X509 CRL-----";
    public static final String END_X509_CRL_KEY = "-----END X509 CRL-----";
    public static final String BEGIN_PKCS7 = "-----BEGIN PKCS7-----";
    public static final String END_PKCS7 = "-----END PKCS7-----";

    @Deprecated
    public static X500Name stringToBcX500Name(String dn) {
        return DnComponents.stringToBcX500Name(dn);
    }

    @Deprecated
    public static X500Name stringToBcX500Name(String dn, boolean ldapOrder) {
        return DnComponents.stringToBcX500Name(dn, ldapOrder);
    }

    @Deprecated
    public static X500Name stringToBcX500Name(String dn, X500NameStyle nameStyle, boolean ldaporder) {
        return DnComponents.stringToBcX500Name(dn, nameStyle, ldaporder);
    }

    @Deprecated
    public static X500Name stringToBcX500Name(String dn, X500NameStyle nameStyle, boolean ldaporder, String[] order) {
        return DnComponents.stringToBcX500Name(dn, nameStyle, ldaporder, order);
    }

    @Deprecated
    public static X500Name stringToBcX500Name(String dn, X500NameStyle nameStyle, boolean ldaporder, String[] order, boolean applyLdapToCustomOrder) {
        return DnComponents.stringToBcX500Name(dn, nameStyle, ldaporder, order, applyLdapToCustomOrder);
    }

    @Deprecated
    public static X500Name stringToUnorderedX500Name(String dn, X500NameStyle nameStyle) {
        return DnComponents.stringToUnorderedX500Name(dn, nameStyle);
    }

    @Deprecated
    public static String getUnescapedPlus(String value) {
        return DnComponents.getUnescapedPlus(value);
    }

    public static String getCertSignatureAlgorithmNameAsString(Certificate cert) {
        String certSignatureAlgorithm;
        String certSignatureAlgorithmTmp = CertificateImplementationRegistry.INSTANCE.getCertificateImplementation(cert.getType()).getCertificateSignatureAlgorithm(cert);
        if (certSignatureAlgorithmTmp.equalsIgnoreCase(PKCSObjectIdentifiers.id_RSASSA_PSS.getId()) && cert instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate)cert;
            byte[] params = x509cert.getSigAlgParams();
            RSASSAPSSparams rsaParams = RSASSAPSSparams.getInstance((Object)params);
            String digestName = MessageDigestUtils.getDigestName((ASN1ObjectIdentifier)rsaParams.getHashAlgorithm().getAlgorithm());
            if (digestName.contains("-") && !digestName.startsWith("SHA3")) {
                digestName = StringUtils.remove((String)digestName, (char)'-');
            }
            certSignatureAlgorithm = digestName + "withRSAandMGF1";
        } else {
            certSignatureAlgorithm = certSignatureAlgorithmTmp;
        }
        if (((String)certSignatureAlgorithm).equalsIgnoreCase(EdECObjectIdentifiers.id_Ed25519.getId())) {
            return "Ed25519";
        }
        if (((String)certSignatureAlgorithm).equalsIgnoreCase(EdECObjectIdentifiers.id_Ed448.getId())) {
            return "Ed448";
        }
        if (((String)certSignatureAlgorithm).equalsIgnoreCase(X9ObjectIdentifiers.ecdsa_with_SHA256.getId())) {
            return "SHA256withECDSA";
        }
        return certSignatureAlgorithm;
    }

    @Deprecated
    public static String stringToBCDNString(String dn) {
        return DnComponents.stringToBCDNString(dn);
    }

    @Deprecated
    public static List<String> getEmailFromDN(String dn) {
        return DnComponents.getEmailFromDN(dn);
    }

    @Deprecated
    public static String getEMailAddress(Certificate certificate) {
        return DnComponents.getEMailAddress(certificate);
    }

    @Deprecated
    public static String reverseDN(String dn) {
        return DnComponents.reverseDN(dn);
    }

    @Deprecated
    public static boolean isDNReversed(String dn) {
        return DnComponents.isDNReversed(dn);
    }

    @Deprecated
    public static boolean dnHasMultipleComponents(String dn) {
        return DnComponents.dnHasMultipleComponents(dn);
    }

    @Deprecated
    public static String getPartFromDN(String dn, String dnpart) {
        return DnComponents.getPartFromDN(dn, dnpart);
    }

    @Deprecated
    public static List<String> getPartsFromDN(String dn, String dnpart) {
        return DnComponents.getPartsFromDN(dn, dnpart);
    }

    @Deprecated
    public static List<String> getCustomOids(String dn) {
        return DnComponents.getCustomOids(dn);
    }

    public static String getSubjectDN(Certificate cert) {
        if (cert == null || CertificateImplementationRegistry.INSTANCE.getCertificateImplementation(cert.getType()) == null) {
            return "";
        }
        return CertificateImplementationRegistry.INSTANCE.getCertificateImplementation(cert.getType()).getSubjectDn(cert);
    }

    @Deprecated
    public static String getUnescapedRdnValue(String value) {
        return DnComponents.getUnescapedRdnValue(value);
    }

    public static String getIssuerDN(Certificate cert) {
        if (cert == null || CertificateImplementationRegistry.INSTANCE.getCertificateImplementation(cert.getType()) == null) {
            return "";
        }
        return CertificateImplementationRegistry.INSTANCE.getCertificateImplementation(cert.getType()).getIssuerDn(cert);
    }

    public static BigInteger getSerialNumber(Certificate cert) {
        if (cert == null) {
            throw new IllegalArgumentException("Null input");
        }
        return CertificateImplementationRegistry.INSTANCE.getCertificateImplementation(cert.getType()).getSerialNumber(cert);
    }

    public static BigInteger getSerialNumberFromString(String sernoString) {
        BigInteger ret;
        if (sernoString == null) {
            throw new IllegalArgumentException("getSerialNumberFromString: sernoString is null");
        }
        try {
            if (sernoString.length() != 5) {
                ret = new BigInteger(sernoString, 16);
            } else if (NumberUtils.isNumber((String)sernoString)) {
                ret = NumberUtils.createBigInteger((String)sernoString);
            } else {
                log.info((Object)"getSerialNumber: Sequence is not a numeric string, trying to extract numerical sequence part.");
                StringBuilder buf = new StringBuilder();
                for (int i = 0; i < sernoString.length(); ++i) {
                    char c = sernoString.charAt(i);
                    if (!CharUtils.isAsciiNumeric((char)c)) continue;
                    buf.append(c);
                }
                if (buf.length() > 0) {
                    ret = NumberUtils.createBigInteger((String)buf.toString());
                } else {
                    log.info((Object)"getSerialNumber: can not extract numeric sequence part, trying alfanumeric value (radix 36).");
                    if (sernoString.matches("[0-9A-Z]{1,5}")) {
                        int numSeq = Integer.parseInt(sernoString, 36);
                        ret = BigInteger.valueOf(numSeq);
                    } else {
                        log.info((Object)"getSerialNumber: Sequence does not contain any numeric parts, returning 0.");
                        ret = BigInteger.valueOf(0L);
                    }
                }
            }
        }
        catch (NumberFormatException e) {
            log.debug((Object)("getSerialNumber: NumberFormatException for sequence: " + sernoString));
            ret = BigInteger.valueOf(0L);
        }
        return ret;
    }

    public static String getSerialNumberAsString(Certificate cert) {
        if (cert == null) {
            throw new IllegalArgumentException("Certificate was null");
        }
        return CertificateImplementationRegistry.INSTANCE.getCertificateImplementation(cert.getType()).getSerialNumberAsString(cert);
    }

    public static byte[] getSignature(Certificate cert) {
        if (cert == null) {
            return new byte[0];
        }
        return CertificateImplementationRegistry.INSTANCE.getCertificateImplementation(cert.getType()).getSignature(cert);
    }

    public static String getIssuerDN(X509CRL crl) {
        String dn = null;
        try {
            CertificateFactory cf = CertTools.getCertificateFactory();
            X509CRL x509crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(crl.getEncoded()));
            dn = X500Name.getInstance((X500NameStyle)CeSecoreNameStyle.INSTANCE, (Object)x509crl.getIssuerX500Principal().getEncoded()).toString();
        }
        catch (CRLException ce) {
            log.error((Object)"CRLException: ", (Throwable)ce);
            return null;
        }
        return DnComponents.stringToBCDNString(dn);
    }

    public static Date getNotBefore(Certificate cert) {
        if (cert == null) {
            throw new IllegalArgumentException("getNotBefore: cert is null");
        }
        return CertificateImplementationRegistry.INSTANCE.getCertificateImplementation(cert.getType()).getNotBefore(cert);
    }

    public static Date getNotAfter(Certificate cert) {
        if (cert == null) {
            throw new IllegalArgumentException("getNotAfter: cert is null");
        }
        return CertificateImplementationRegistry.INSTANCE.getCertificateImplementation(cert.getType()).getNotAfter(cert);
    }

    public static CertificateFactory getCertificateFactory(String provider) {
        String prov = provider == null ? "BC" : provider;
        if ("BC".equals(prov)) {
            CryptoProviderTools.installBCProviderIfNotAvailable();
        }
        try {
            return CertificateFactory.getInstance("X.509", prov);
        }
        catch (NoSuchProviderException nspe) {
            log.error((Object)"NoSuchProvider: ", (Throwable)nspe);
        }
        catch (CertificateException ce) {
            log.error((Object)"CertificateException: ", (Throwable)ce);
        }
        return null;
    }

    public static CertificateFactory getCertificateFactory() {
        return CertTools.getCertificateFactory("BC");
    }

    @Deprecated
    public static List<Certificate> getCertsFromPEM(String certFilename) throws FileNotFoundException, CertificateParsingException {
        return CertTools.getCertsFromPEM(certFilename, Certificate.class);
    }

    public static <T extends Certificate> List<T> getCertsFromPEM(String certFilename, Class<T> returnType) throws FileNotFoundException, CertificateParsingException {
        List<T> certs;
        if (log.isTraceEnabled()) {
            log.trace((Object)(">getCertfromPEM: certFilename=" + certFilename));
        }
        try (FileInputStream inStrm = new FileInputStream(certFilename);){
            certs = CertTools.getCertsFromPEM(inStrm, returnType);
        }
        catch (IOException e) {
            throw new IllegalStateException("Failed to close input stream");
        }
        if (log.isTraceEnabled()) {
            log.trace((Object)("<getCertfromPEM: certFile=" + certFilename));
        }
        return certs;
    }

    public static final byte[] readCertificateChainAsArrayOrThrow(String file) throws FileNotFoundException, IOException, CertificateParsingException, CertificateEncodingException {
        ArrayList<byte[]> cachain = new ArrayList<byte[]>();
        try (FileInputStream fis = new FileInputStream(file);){
            List<Certificate> certs = CertTools.getCertsFromPEM(fis, Certificate.class);
            for (Certificate cert : certs) {
                cachain.add(cert.getEncoded());
            }
        }
        catch (CertificateParsingException e) {
            byte[] certbytes = FileTools.readFiletoBuffer(file);
            Certificate cert = CertTools.getCertfromByteArray(certbytes, Certificate.class);
            cachain.add(cert.getEncoded());
        }
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();){
            for (byte[] bytes : cachain) {
                bos.write(bytes);
            }
            Object object = bos.toByteArray();
            return object;
        }
    }

    public static final List<CertificateWrapper> bytesToListOfCertificateWrapperOrThrow(byte[] bytes) throws CertificateParsingException {
        List<Certificate> certs = null;
        try {
            certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(bytes), Certificate.class);
        }
        catch (CertificateException e) {
            log.debug((Object)("Input stream is not PEM certificate(s): " + e.getMessage()));
            Certificate cert = CertTools.getCertfromByteArray(bytes, Certificate.class);
            certs = new ArrayList<Certificate>();
            certs.add(cert);
        }
        return EJBTools.wrapCertCollection(certs);
    }

    @Deprecated
    public static List<Certificate> getCertsFromPEM(InputStream certstream) throws CertificateParsingException {
        return CertTools.getCertsFromPEM(certstream, Certificate.class);
    }

    public static <T extends Certificate> List<T> getCertsFromPEM(InputStream certstream, Class<T> returnType) throws CertificateParsingException {
        if (log.isTraceEnabled()) {
            log.trace((Object)">getCertfromPEM");
        }
        ArrayList<T> ret = new ArrayList<T>();
        String beginKeyTrust = "-----BEGIN TRUSTED CERTIFICATE-----";
        String endKeyTrust = "-----END TRUSTED CERTIFICATE-----";
        try (BufferedReader bufRdr = new BufferedReader(new InputStreamReader(new SecurityFilterInputStream(certstream)));){
            while (bufRdr.ready()) {
                String temp;
                ByteArrayOutputStream ostr = new ByteArrayOutputStream();
                PrintStream opstr = new PrintStream(ostr);
                while ((temp = bufRdr.readLine()) != null && !temp.equals(BEGIN_CERTIFICATE) && !temp.equals(beginKeyTrust)) {
                }
                if (temp == null) {
                    if (ret.isEmpty()) {
                        throw new CertificateParsingException("Error in " + certstream.toString() + ", missing -----BEGIN CERTIFICATE----- boundary");
                    }
                    break;
                }
                while ((temp = bufRdr.readLine()) != null && !temp.equals(END_CERTIFICATE) && !temp.equals(endKeyTrust)) {
                    opstr.print(temp);
                }
                if (temp == null) {
                    throw new IllegalArgumentException("Error in " + certstream.toString() + ", missing -----END CERTIFICATE----- boundary");
                }
                opstr.close();
                byte[] certbuf = Base64.decode(ostr.toByteArray());
                ostr.close();
                T cert = CertTools.getCertfromByteArray(certbuf, returnType);
                ret.add(cert);
            }
        }
        catch (IOException e) {
            throw new IllegalStateException("Exception caught when attempting to read stream, see underlying IOException", e);
        }
        if (log.isTraceEnabled()) {
            log.trace((Object)("<getcertfromPEM:" + ret.size()));
        }
        return ret;
    }

    public static List<Certificate> getCertCollectionFromArray(Certificate[] certs, String provider) throws CertificateException, NoSuchProviderException {
        if (log.isTraceEnabled()) {
            log.trace((Object)(">getCertCollectionFromArray: " + provider));
        }
        ArrayList<Certificate> ret = new ArrayList<Certificate>();
        String prov = provider;
        if (prov == null) {
            prov = "BC";
        }
        for (Certificate cert : certs) {
            Certificate newcert = CertTools.getCertfromByteArray(cert.getEncoded(), prov);
            ret.add(newcert);
        }
        if (log.isTraceEnabled()) {
            log.trace((Object)("<getCertCollectionFromArray: " + ret.size()));
        }
        return ret;
    }

    @Deprecated
    public static byte[] getPEMFromCerts(Collection<Certificate> certs) throws CertificateException {
        return CertTools.getPemFromCertificateChain(certs);
    }

    public static byte[] getPemFromCertificateChain(Collection<Certificate> certs) throws CertificateEncodingException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (PrintStream printStream = new PrintStream(baos);){
            for (Certificate certificate : certs) {
                if (certificate == null) continue;
                printStream.println("Subject: " + CertTools.getSubjectDN(certificate));
                printStream.println("Issuer: " + CertTools.getIssuerDN(certificate));
                CertTools.writeAsPemEncoded(printStream, certificate.getEncoded(), BEGIN_CERTIFICATE, END_CERTIFICATE);
            }
        }
        return baos.toByteArray();
    }

    public static String getPemFromCertificate(Certificate certificate) throws CertificateEncodingException {
        byte[] enccert = certificate.getEncoded();
        byte[] b64cert = Base64.encode(enccert);
        Object out = BEGIN_CERTIFICATE_WITH_NL;
        out = (String)out + new String(b64cert);
        out = (String)out + END_CERTIFICATE_WITH_NL;
        return out;
    }

    public static String getPemFromCertificates(List<Certificate> certificates) throws CertificateEncodingException {
        StringBuilder sb = new StringBuilder();
        for (Certificate certificate : certificates) {
            sb.append(BEGIN_CERTIFICATE_WITH_NL).append(new String(Base64.encode(certificate.getEncoded()))).append(END_CERTIFICATE_WITH_NL);
        }
        return sb.toString();
    }

    public static byte[] getPEMFromCrl(byte[] crlBytes) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (PrintStream printStream = new PrintStream(baos);){
            CertTools.writeAsPemEncoded(printStream, crlBytes, BEGIN_X509_CRL_KEY, END_X509_CRL_KEY);
        }
        return baos.toByteArray();
    }

    public static byte[] getPEMFromPublicKey(byte[] publicKeyBytes) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (PrintStream printStream = new PrintStream(baos);){
            CertTools.writeAsPemEncoded(printStream, publicKeyBytes, BEGIN_PUBLIC_KEY, END_PUBLIC_KEY);
        }
        return baos.toByteArray();
    }

    public static byte[] getPEMFromPrivateKey(byte[] privateKeyBytes) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (PrintStream printStream = new PrintStream(baos);){
            CertTools.writeAsPemEncoded(printStream, privateKeyBytes, BEGIN_PRIVATE_KEY, END_PRIVATE_KEY);
        }
        return baos.toByteArray();
    }

    public static byte[] getPEMFromCertificateRequest(byte[] certificateRequestBytes) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (PrintStream printStream = new PrintStream(baos);){
            CertTools.writeAsPemEncoded(printStream, certificateRequestBytes, BEGIN_CERTIFICATE_REQUEST, END_CERTIFICATE_REQUEST);
        }
        return baos.toByteArray();
    }

    public static byte[] getPemFromPkcs7(byte[] pkcs7Binary) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (PrintStream printStream = new PrintStream(baos);){
            CertTools.writeAsPemEncoded(printStream, pkcs7Binary, BEGIN_PKCS7, END_PKCS7);
        }
        return baos.toByteArray();
    }

    private static void writeAsPemEncoded(PrintStream printStream, byte[] unencodedData, String beginKey, String endKey) {
        printStream.println(beginKey);
        printStream.println(new String(Base64.encode(unencodedData)));
        printStream.println(endKey);
    }

    @Deprecated
    public static Certificate getCertfromByteArray(byte[] cert, String provider) throws CertificateParsingException {
        return CertTools.getCertfromByteArray(cert, provider, Certificate.class);
    }

    public static <T extends Certificate> T getCertfromByteArray(byte[] cert, String provider, Class<T> returnType) throws CertificateParsingException {
        return CertificateImplementationRegistry.INSTANCE.getCertfromByteArray(cert, provider, returnType);
    }

    @Deprecated
    public static Certificate getCertfromByteArray(byte[] cert) throws CertificateParsingException {
        return CertTools.getCertfromByteArray(cert, Certificate.class);
    }

    public static <T extends Certificate> T getCertfromByteArray(byte[] cert, Class<T> returnType) throws CertificateParsingException {
        return CertTools.getCertfromByteArray(cert, "BC", returnType);
    }

    public static X509CRL getCRLfromByteArray(byte[] crl) throws CRLException {
        log.trace((Object)">getCRLfromByteArray");
        if (crl == null) {
            throw new CRLException("No content in crl byte array");
        }
        CertificateFactory cf = CertTools.getCertificateFactory();
        X509CRL x509crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(crl));
        log.trace((Object)"<getCRLfromByteArray");
        return x509crl;
    }

    public static String buildCsr(PKCS10CertificationRequest pkcs10CertificationRequest) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("-----BEGIN CERTIFICATE REQUEST-----\n");
        try {
            stringBuilder.append(new String(Base64.encode(pkcs10CertificationRequest.getEncoded())));
        }
        catch (IOException e) {
            throw new IllegalArgumentException("PKCS10 request could not be encoded", e);
        }
        stringBuilder.append("\n-----END CERTIFICATE REQUEST-----\n");
        return stringBuilder.toString();
    }

    public static boolean isSelfSigned(Certificate cert) {
        if (log.isTraceEnabled()) {
            log.trace((Object)(">isSelfSigned: cert: " + CertTools.getIssuerDN(cert) + "\n" + CertTools.getSubjectDN(cert)));
        }
        boolean ret = CertTools.getSubjectDN(cert).equals(CertTools.getIssuerDN(cert));
        if (log.isTraceEnabled()) {
            log.trace((Object)("<isSelfSigned:" + ret));
        }
        return ret;
    }

    public static boolean isCertificateValid(X509Certificate certificate, boolean warnIfAboutToExpire, long warnBeforeExpirationTime) {
        try {
            certificate.checkValidity();
        }
        catch (CertificateExpiredException e) {
            if (log.isDebugEnabled()) {
                log.debug((Object)("The certificate with serial number '" + certificate.getSerialNumber().toString(16) + "' issued by the CA '" + CertTools.getIssuerDN(certificate) + "' has expired."));
            }
            return false;
        }
        catch (CertificateNotYetValidException e) {
            if (log.isDebugEnabled()) {
                log.debug((Object)("The certificate with serial number '" + certificate.getSerialNumber().toString(16) + "' issued by the CA '" + CertTools.getIssuerDN(certificate) + "' is not yet valid."));
            }
            return false;
        }
        if (warnBeforeExpirationTime < 1L) {
            return true;
        }
        Date warnDate = new Date(new Date().getTime() + warnBeforeExpirationTime);
        try {
            certificate.checkValidity(warnDate);
        }
        catch (CertificateExpiredException e) {
            if (warnIfAboutToExpire || log.isDebugEnabled()) {
                Level logLevel = warnIfAboutToExpire ? Level.WARN : Level.DEBUG;
                log.log((Priority)logLevel, (Object)("The certificate with serial number '" + certificate.getSerialNumber().toString(16) + "' issued by the CA '" + CertTools.getIssuerDN(certificate) + "' will expire at '" + certificate.getNotAfter() + "'."));
            }
        }
        catch (CertificateNotYetValidException e) {
            throw new IllegalStateException("This should never happen.", e);
        }
        if (log.isDebugEnabled()) {
            log.debug((Object)("Time for \"certificate will soon expire\" not yet reached. You will be warned after: " + new Date(certificate.getNotAfter().getTime() - warnBeforeExpirationTime)));
        }
        return true;
    }

    public static boolean isCA(Certificate cert) {
        return CertificateImplementationRegistry.INSTANCE.getCertificateImplementation(cert.getType()).isCA(cert);
    }

    public static boolean isOCSPCert(X509Certificate cert) {
        List<String> keyUsages;
        try {
            keyUsages = cert.getExtendedKeyUsage();
        }
        catch (CertificateParsingException e) {
            return false;
        }
        return keyUsages != null && keyUsages.contains(KeyPurposeId.id_kp_OCSPSigning.getId());
    }

    @Deprecated
    public static X509Certificate genSelfCert(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg, boolean isCA) throws OperatorCreationException, CertificateException {
        return CertTools.genSelfCert(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, CryptoProviderTools.getProviderNameFromAlg(sigAlg));
    }

    @Deprecated
    public static X509Certificate genSelfCert(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg, boolean isCA, String provider, boolean ldapOrder) throws CertificateParsingException, OperatorCreationException {
        int keyUsage = isCA ? 6 : 0;
        return CertTools.genSelfCertForPurpose(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, keyUsage, null, null, provider, ldapOrder);
    }

    @Deprecated
    public static X509Certificate genSelfCert(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg, boolean isCA, String provider) throws OperatorCreationException, CertificateException {
        return CertTools.genSelfCert(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, provider, true);
    }

    @Deprecated
    public static X509Certificate genSelfCertForPurpose(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg, boolean isCA, int keyusage, boolean ldapOrder) throws CertificateParsingException, OperatorCreationException {
        return CertTools.genSelfCertForPurpose(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, keyusage, null, null, "BC", ldapOrder);
    }

    @Deprecated
    public static X509Certificate genSelfCertForPurpose(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg, boolean isCA, int keyusage, Date privateKeyNotBefore, Date privateKeyNotAfter, String provider) throws CertificateParsingException, OperatorCreationException {
        return CertTools.genSelfCertForPurpose(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, keyusage, privateKeyNotBefore, privateKeyNotAfter, provider, true);
    }

    @Deprecated
    public static X509Certificate genSelfCertForPurpose(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg, boolean isCA, int keyusage, Date privateKeyNotBefore, Date privateKeyNotAfter, String provider, boolean ldapOrder) throws CertificateParsingException, OperatorCreationException {
        try {
            return CertTools.genSelfCertForPurpose(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, keyusage, privateKeyNotBefore, privateKeyNotAfter, provider, ldapOrder, null);
        }
        catch (CertIOException e) {
            throw new IllegalStateException("CertIOException was thrown due to an invalid extension, but no extensions were provided.", e);
        }
    }

    @Deprecated
    public static X509Certificate genSelfCertForPurpose(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg, boolean isCA, int keyusage, Date privateKeyNotBefore, Date privateKeyNotAfter, String provider, boolean ldapOrder, List<Extension> additionalExtensions) throws CertificateParsingException, OperatorCreationException, CertIOException {
        Date firstDate = new Date();
        firstDate.setTime(firstDate.getTime() - 600000L);
        Date lastDate = new Date();
        lastDate.setTime(lastDate.getTime() + validity * 86400000L);
        return CertTools.genSelfCertForPurpose(dn, firstDate, lastDate, policyId, privKey, pubKey, sigAlg, isCA, keyusage, privateKeyNotBefore, privateKeyNotAfter, provider, ldapOrder, additionalExtensions);
    }

    @Deprecated
    public static X509Certificate genSelfCertForPurpose(String dn, Date firstDate, Date lastDate, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg, boolean isCA, int keyusage, Date privateKeyNotBefore, Date privateKeyNotAfter, String provider, boolean ldapOrder, List<Extension> additionalExtensions) throws CertificateParsingException, OperatorCreationException, CertIOException {
        return CertTools.genCertForPurpose(dn, dn, firstDate, lastDate, policyId, privKey, pubKey, sigAlg, isCA, keyusage, privateKeyNotBefore, privateKeyNotAfter, provider, ldapOrder, additionalExtensions);
    }

    public static byte[] getAuthorityKeyId(Certificate certificate) {
        ASN1Primitive asn1Sequence;
        if (certificate != null && certificate instanceof X509Certificate && (asn1Sequence = CertTools.getExtensionValue((X509Certificate)certificate, Extension.authorityKeyIdentifier.getId())) != null) {
            return AuthorityKeyIdentifier.getInstance((Object)asn1Sequence).getKeyIdentifier();
        }
        return null;
    }

    public static byte[] getSubjectKeyId(Certificate certificate) {
        ASN1Primitive asn1Sequence;
        if (certificate != null && certificate instanceof X509Certificate && (asn1Sequence = CertTools.getExtensionValue((X509Certificate)certificate, Extension.subjectKeyIdentifier.getId())) != null) {
            return SubjectKeyIdentifier.getInstance((Object)asn1Sequence).getKeyIdentifier();
        }
        return null;
    }

    public static byte[] getAuthorityKeyId(X509CRL crl) {
        ASN1Primitive asn1Sequence = CertTools.getDerObjectFromByteArray(crl.getExtensionValue(Extension.authorityKeyIdentifier.getId()));
        if (asn1Sequence != null) {
            return AuthorityKeyIdentifier.getInstance((Object)asn1Sequence).getKeyIdentifier();
        }
        return null;
    }

    public static String getCertificatePolicyId(Certificate certificate, int pos) throws IOException {
        ASN1Sequence asn1Sequence;
        if (certificate != null && certificate instanceof X509Certificate && (asn1Sequence = ASN1Sequence.getInstance((Object)CertTools.getExtensionValue((X509Certificate)certificate, Extension.certificatePolicies.getId()))) != null && asn1Sequence.size() >= pos + 1) {
            return PolicyInformation.getInstance((Object)asn1Sequence.getObjectAt(pos)).getPolicyIdentifier().getId();
        }
        return null;
    }

    public static List<ASN1ObjectIdentifier> getCertificatePolicyIds(Certificate certificate) throws IOException {
        ASN1Sequence asn1Sequence;
        ArrayList<ASN1ObjectIdentifier> ret = new ArrayList<ASN1ObjectIdentifier>();
        if (certificate != null && certificate instanceof X509Certificate && (asn1Sequence = ASN1Sequence.getInstance((Object)CertTools.getExtensionValue((X509Certificate)certificate, Extension.certificatePolicies.getId()))) != null) {
            for (ASN1Encodable asn1Encodable : asn1Sequence) {
                PolicyInformation pi = PolicyInformation.getInstance((Object)asn1Encodable);
                ret.add(pi.getPolicyIdentifier());
            }
        }
        return ret;
    }

    public static List<PolicyInformation> getCertificatePolicies(Certificate certificate) throws IOException {
        ASN1Sequence asn1Sequence;
        ArrayList<PolicyInformation> ret = new ArrayList<PolicyInformation>();
        if (certificate != null && certificate instanceof X509Certificate && (asn1Sequence = ASN1Sequence.getInstance((Object)CertTools.getExtensionValue((X509Certificate)certificate, Extension.certificatePolicies.getId()))) != null) {
            for (ASN1Encodable asn1Encodable : asn1Sequence) {
                PolicyInformation pi = PolicyInformation.getInstance((Object)asn1Encodable);
                ret.add(pi);
            }
        }
        return ret;
    }

    @Deprecated
    public static String getUPNAltName(Certificate cert) throws CertificateParsingException {
        return DnComponents.getUPNAltName(cert);
    }

    @Deprecated
    public static X509Certificate genCertForPurpose(String subjectDn, String issuerDn, Date firstDate, Date lastDate, String policyId, PrivateKey issuerPrivKey, PublicKey entityPubKey, String sigAlg, boolean isCA, int keyusage, Date privateKeyNotBefore, Date privateKeyNotAfter, String provider, boolean ldapOrder, List<Extension> additionalExtensions) throws CertificateParsingException, OperatorCreationException, CertIOException {
        SimpleCertGenerator certGen = new SimpleCertGenerator();
        certGen.setSubjectDn(subjectDn);
        certGen.setIssuerDn(issuerDn);
        certGen.setFirstDate(firstDate);
        certGen.setLastDate(lastDate);
        certGen.setPolicyId(policyId);
        certGen.setIssuerPrivKey(issuerPrivKey);
        certGen.setEntityPubKey(entityPubKey);
        certGen.setSignatureAlgorithm(sigAlg);
        certGen.setCa(isCA);
        certGen.setKeyUsage(keyusage);
        certGen.setPrivateKeyNotBefore(privateKeyNotBefore);
        certGen.setPrivateKeyNotAfter(privateKeyNotAfter);
        certGen.setProvider(provider);
        certGen.setLdapOrder(ldapOrder);
        certGen.setAdditionalExtensions(additionalExtensions);
        return certGen.generateCertificate();
    }

    @Deprecated
    public static String getUTF8AltNameOtherName(Certificate cert, String oid) throws CertificateParsingException {
        return DnComponents.getUTF8AltNameOtherName(cert, oid);
    }

    @Deprecated
    public static String getPermanentIdentifierAltName(Certificate cert) throws CertificateParsingException {
        return DnComponents.getPermanentIdentifierAltName(cert);
    }

    @Deprecated
    public static String getGuidAltName(Certificate cert) throws CertificateParsingException {
        return DnComponents.getGuidAltName(cert);
    }

    @Deprecated
    public static String getAltNameStringFromExtension(Extension ext) {
        return DnComponents.getAltNameStringFromExtension(ext);
    }

    @Deprecated
    public static GeneralNames getGeneralNamesFromExtension(Extension ext) {
        return DnComponents.getGeneralNamesFromExtension(ext);
    }

    @Deprecated
    public static String getSubjectAlternativeName(Certificate certificate) {
        return DnComponents.getSubjectAlternativeName(certificate);
    }

    @Deprecated
    public static GeneralNames getGeneralNamesFromAltName(String altName) {
        return DnComponents.getGeneralNamesFromAltName(altName);
    }

    @Deprecated
    public static String getGeneralNameString(int tag, ASN1Encodable value) throws IOException {
        return DnComponents.getGeneralNameString(tag, value);
    }

    public static boolean verify(X509Certificate certificate, Collection<X509Certificate> caCertChain, Date date, PKIXCertPathChecker ... pkixCertPathCheckers) throws CertPathValidatorException {
        if (caCertChain == null || caCertChain.isEmpty()) {
            throw new CertPathValidatorException("Chain is missing.");
        }
        try {
            ArrayList<X509Certificate> certlist = new ArrayList<X509Certificate>();
            certlist.add(certificate);
            CertPath cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certlist);
            X509Certificate[] cac = caCertChain.toArray(new X509Certificate[caCertChain.size()]);
            TrustAnchor anchor = new TrustAnchor(cac[0], null);
            PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
            for (PKIXCertPathChecker pkixCertPathChecker : pkixCertPathCheckers) {
                params.addCertPathChecker(pkixCertPathChecker);
            }
            params.setRevocationEnabled(false);
            params.setDate(date);
            CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)cpv.validate(cp, params);
            if (log.isDebugEnabled()) {
                log.debug((Object)("Certificate verify result by TrustAnchor: " + result.getTrustAnchor().toString()));
            }
        }
        catch (CertPathValidatorException cpve) {
            throw new CertPathValidatorException("Invalid certificate or certificate not issued by specified CA: " + cpve.getMessage());
        }
        catch (CertificateException e) {
            throw new IllegalArgumentException("Something was wrong with the supplied certificate", e);
        }
        catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle provider not found.", e);
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm PKIX was not found.", e);
        }
        catch (InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException("Either ca certificate chain was empty, or the certificate was on an inappropraite type for a PKIX path checker.", e);
        }
        return true;
    }

    public static boolean verify(X509Certificate certificate, Collection<X509Certificate> caCertChain) throws CertPathValidatorException {
        return CertTools.verify(certificate, caCertChain, null, new PKIXCertPathChecker[0]);
    }

    public static boolean verifyWithTrustedCertificates(X509Certificate certificate, List<Collection<X509Certificate>> trustedCertificates, PKIXCertPathChecker ... pkixCertPathCheckers) {
        if (trustedCertificates == null) {
            if (log.isDebugEnabled()) {
                log.debug((Object)"Input of trustedCertificates was null. Trusting nothing.");
            }
            return false;
        }
        if (trustedCertificates.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug((Object)"Input of trustedCertificates was empty. Trusting everything.");
            }
            return true;
        }
        BigInteger certSN = CertTools.getSerialNumber(certificate);
        for (Collection<X509Certificate> trustedCertChain : trustedCertificates) {
            X509Certificate trustedCert = trustedCertChain.iterator().next();
            BigInteger trustedCertSN = CertTools.getSerialNumber(trustedCert);
            if (certSN.equals(trustedCertSN) && trustedCertChain.size() > 1) {
                trustedCertChain.remove(trustedCert);
            }
            try {
                CertTools.verify(certificate, trustedCertChain, null, pkixCertPathCheckers);
                if (log.isTraceEnabled()) {
                    log.trace((Object)("Trusting certificate with SubjectDN '" + CertTools.getSubjectDN(certificate) + "' and issuerDN '" + CertTools.getIssuerDN(certificate) + "'."));
                }
                return true;
            }
            catch (CertPathValidatorException certPathValidatorException) {
            }
        }
        return false;
    }

    public static void checkValidity(Certificate cert, Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        if (cert != null) {
            CertificateImplementationRegistry.INSTANCE.getCertificateImplementation(cert.getType()).checkValidity(cert, date);
        }
    }

    public static String getCrlDistributionPoint(Certificate certificate) {
        X509Certificate x509cert;
        List<String> cdps;
        if (certificate instanceof X509Certificate && !(cdps = CertTools.getCrlDistributionPoints(x509cert = (X509Certificate)certificate, true)).isEmpty()) {
            return (String)cdps.iterator().next();
        }
        return null;
    }

    public static List<String> getCrlDistributionPoints(X509Certificate x509cert) {
        return CertTools.getCrlDistributionPoints(x509cert, false);
    }

    public static List<String> getCrlDistributionPoints(ASN1Primitive extensionValue) {
        return CertTools.getCrlDistributionPoints(extensionValue, false);
    }

    private static List<String> getCrlDistributionPoints(X509Certificate x509cert, boolean onlyfirst) {
        ASN1Primitive extensionValue = CertTools.getExtensionValue(x509cert, Extension.cRLDistributionPoints.getId());
        if (extensionValue == null) {
            return Collections.emptyList();
        }
        return CertTools.getCrlDistributionPoints(extensionValue, onlyfirst);
    }

    private static List<String> getCrlDistributionPoints(ASN1Primitive extensionValue, boolean onlyfirst) {
        ArrayList<String> cdps = new ArrayList<String>();
        ASN1Sequence crlDistributionPoints = ASN1Sequence.getInstance((Object)extensionValue);
        for (int i = 0; i < crlDistributionPoints.size(); ++i) {
            ASN1Sequence distributionPoint = ASN1Sequence.getInstance((Object)crlDistributionPoints.getObjectAt(i));
            for (int j = 0; j < distributionPoint.size(); ++j) {
                block5: {
                    ASN1TaggedObject tagged = ASN1TaggedObject.getInstance((Object)distributionPoint.getObjectAt(j));
                    if (tagged.getTagNo() != 0) continue;
                    String url = CertTools.getStringFromGeneralNames(tagged.getBaseObject().toASN1Primitive());
                    if (url != null) {
                        try {
                            new URI(url);
                            cdps.add(url);
                        }
                        catch (URISyntaxException e) {
                            if (!log.isDebugEnabled()) break block5;
                            log.debug((Object)("Error parsing '" + url + "' as a URI. " + e.getLocalizedMessage()));
                        }
                    }
                }
                if (!onlyfirst) continue;
                return cdps;
            }
        }
        return cdps;
    }

    public static List<String> getCrlDistributionPoints(X509CRL crl) {
        try {
            ASN1Primitive extensionValue = CertTools.getExtensionValue(crl, Extension.issuingDistributionPoint.getId());
            if (extensionValue == null) {
                return Collections.emptyList();
            }
            IssuingDistributionPoint idp = IssuingDistributionPoint.getInstance((Object)extensionValue);
            DistributionPointName dpName = idp.getDistributionPoint();
            if (dpName == null || dpName.getType() != 0) {
                return Collections.emptyList();
            }
            ArrayList<String> uris = new ArrayList<String>();
            GeneralNames generalNames = GeneralNames.getInstance((Object)dpName.getName());
            for (GeneralName generalName : generalNames.getNames()) {
                if (generalName.getTagNo() != 6) continue;
                ASN1IA5String asn1Value = ASN1IA5String.getInstance((Object)generalName.getName());
                uris.add(asn1Value.getString());
            }
            return uris;
        }
        catch (IllegalArgumentException e) {
            log.debug((Object)"Malformed CRL Issuance Distribution Point", (Throwable)e);
            return Collections.emptyList();
        }
    }

    public static Collection<String> getAuthorityInformationAccess(CRL crl) {
        AuthorityInformationAccess authorityInformationAccess;
        AccessDescription[] accessDescriptions;
        X509CRL x509crl;
        ASN1Primitive derObject;
        ArrayList<String> result = new ArrayList<String>();
        if (crl instanceof X509CRL && (derObject = CertTools.getExtensionValue(x509crl = (X509CRL)crl, Extension.authorityInfoAccess.getId())) != null && (accessDescriptions = (authorityInformationAccess = AuthorityInformationAccess.getInstance((Object)derObject)).getAccessDescriptions()) != null) {
            for (AccessDescription accessDescription : accessDescriptions) {
                GeneralName generalName;
                if (!accessDescription.getAccessMethod().equals((ASN1Primitive)X509ObjectIdentifiers.id_ad_caIssuers) || (generalName = accessDescription.getAccessLocation()).getTagNo() != 6) continue;
                ASN1Primitive obj = generalName.toASN1Primitive();
                if (obj instanceof ASN1TaggedObject) {
                    obj = ASN1TaggedObject.getInstance((Object)obj).getBaseObject().toASN1Primitive();
                }
                ASN1IA5String deria5String = ASN1IA5String.getInstance((Object)obj);
                result.add(deria5String.getString());
            }
        }
        return result;
    }

    public static List<String> getAuthorityInformationAccessCAIssuerUris(Certificate cert) {
        return CertTools.getAuthorityInformationAccessCaIssuerUris(cert, false);
    }

    public static String getAuthorityInformationAccessOcspUrl(Certificate cert) {
        List<String> urls = CertTools.getAuthorityInformationAccessOcspUrls(cert);
        if (!urls.isEmpty()) {
            return (String)urls.iterator().next();
        }
        return null;
    }

    public static List<String> getAuthorityInformationAccessOcspUrls(Certificate cert) {
        return CertTools.getAuthorityInformationAccessOcspUrls(cert, false);
    }

    private static List<String> getAuthorityInformationAccessCaIssuerUris(Certificate cert, boolean onlyfirst) {
        AccessDescription[] accessDescriptions;
        X509Certificate x509cert;
        ASN1Primitive obj;
        ArrayList<String> urls = new ArrayList<String>();
        if (cert instanceof X509Certificate && (obj = CertTools.getExtensionValue(x509cert = (X509Certificate)cert, Extension.authorityInfoAccess.getId())) != null && (accessDescriptions = AuthorityInformationAccess.getInstance((Object)obj).getAccessDescriptions()) != null) {
            for (AccessDescription accessDescription : accessDescriptions) {
                ASN1IA5String str;
                GeneralName generalName;
                if (!accessDescription.getAccessMethod().equals((ASN1Primitive)X509ObjectIdentifiers.id_ad_caIssuers) || (generalName = accessDescription.getAccessLocation()).getTagNo() != 6) continue;
                ASN1Primitive gnobj = generalName.toASN1Primitive();
                if (gnobj instanceof ASN1TaggedObject) {
                    gnobj = ASN1TaggedObject.getInstance((Object)gnobj).getBaseObject().toASN1Primitive();
                }
                if ((str = ASN1IA5String.getInstance((Object)gnobj)) != null) {
                    urls.add(str.getString());
                }
                if (!onlyfirst) continue;
                return urls;
            }
        }
        return urls;
    }

    private static List<String> getAuthorityInformationAccessOcspUrls(Certificate cert, boolean onlyfirst) {
        AccessDescription[] accessDescriptions;
        X509Certificate x509cert;
        ASN1Primitive obj;
        ArrayList<String> urls = new ArrayList<String>();
        if (cert instanceof X509Certificate && (obj = CertTools.getExtensionValue(x509cert = (X509Certificate)cert, Extension.authorityInfoAccess.getId())) != null && (accessDescriptions = AuthorityInformationAccess.getInstance((Object)obj).getAccessDescriptions()) != null) {
            for (AccessDescription accessDescription : accessDescriptions) {
                ASN1IA5String str;
                GeneralName generalName;
                if (!accessDescription.getAccessMethod().equals((ASN1Primitive)X509ObjectIdentifiers.ocspAccessMethod) || (generalName = accessDescription.getAccessLocation()).getTagNo() != 6) continue;
                ASN1Primitive gnobj = generalName.toASN1Primitive();
                if (gnobj instanceof ASN1TaggedObject) {
                    gnobj = ASN1TaggedObject.getInstance((Object)gnobj).getBaseObject().toASN1Primitive();
                }
                if ((str = ASN1IA5String.getInstance((Object)gnobj)) != null) {
                    urls.add(str.getString());
                }
                if (!onlyfirst) continue;
                return urls;
            }
        }
        return urls;
    }

    public static PrivateKeyUsagePeriod getPrivateKeyUsagePeriod(X509Certificate cert) {
        PrivateKeyUsagePeriod res = null;
        byte[] extvalue = cert.getExtensionValue(Extension.privateKeyUsagePeriod.getId());
        if (extvalue != null && extvalue.length > 0) {
            if (log.isTraceEnabled()) {
                log.trace((Object)("Found a PrivateKeyUsagePeriod in the certificate with subject: " + CertTools.getSubjectDN(cert)));
            }
            res = PrivateKeyUsagePeriod.getInstance((Object)DEROctetString.getInstance((Object)extvalue).getOctets());
        }
        return res;
    }

    public static ASN1Primitive getExtensionValue(X509Certificate cert, String oid) {
        if (cert == null) {
            return null;
        }
        return CertTools.getDerObjectFromByteArray(cert.getExtensionValue(oid));
    }

    protected static ASN1Primitive getExtensionValue(X509CRL crl, String oid) {
        if (crl == null || oid == null) {
            return null;
        }
        return CertTools.getDerObjectFromByteArray(crl.getExtensionValue(oid));
    }

    public static Extension getExtension(PKCS10CertificationRequest pkcs10CertificateRequest, String oid) {
        Extensions extensions;
        if (pkcs10CertificateRequest != null && oid != null && (extensions = CertTools.getPKCS10Extensions(pkcs10CertificateRequest)) != null) {
            return extensions.getExtension(new ASN1ObjectIdentifier(oid));
        }
        return null;
    }

    private static Extensions getPKCS10Extensions(PKCS10CertificationRequest pkcs10CertificateRequest) {
        Attribute[] attributes;
        for (Attribute attribute : attributes = pkcs10CertificateRequest.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
            ASN1Set attributeValues = attribute.getAttrValues();
            if (attributeValues.size() <= 0) continue;
            return Extensions.getInstance((Object)attributeValues.getObjectAt(0));
        }
        return null;
    }

    private static ASN1Primitive getDerObjectFromByteArray(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        try {
            return ASN1Primitive.fromByteArray((byte[])ASN1OctetString.getInstance((Object)bytes).getOctets());
        }
        catch (IOException e) {
            throw new RuntimeException("Caught an unexected IOException", e);
        }
    }

    private static String getStringFromGeneralNames(ASN1Primitive names) {
        ASN1Sequence namesSequence = ASN1Sequence.getInstance((ASN1TaggedObject)ASN1TaggedObject.getInstance((Object)names), (boolean)false);
        if (namesSequence.size() == 0) {
            return null;
        }
        ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance((Object)namesSequence.getObjectAt(0));
        if (taggedObject.getTagNo() != 6) {
            return null;
        }
        return new String(ASN1OctetString.getInstance((ASN1TaggedObject)taggedObject, (boolean)false).getOctets());
    }

    public static String getFingerprintAsString(Certificate cert) {
        if (cert == null) {
            return null;
        }
        try {
            byte[] res = CertTools.generateSHA1Fingerprint(cert.getEncoded());
            return new String(Hex.encode((byte[])res));
        }
        catch (CertificateEncodingException cee) {
            log.error((Object)"Error encoding certificate.", (Throwable)cee);
            return null;
        }
    }

    public static String getFingerprintAsString(X509CRL crl) {
        try {
            byte[] res = CertTools.generateSHA1Fingerprint(crl.getEncoded());
            return new String(Hex.encode((byte[])res));
        }
        catch (CRLException ce) {
            log.error((Object)"Error encoding CRL.", (Throwable)ce);
            return null;
        }
    }

    public static String getFingerprintAsString(byte[] in) {
        byte[] res = CertTools.generateSHA1Fingerprint(in);
        return new String(Hex.encode((byte[])res));
    }

    public static String getSHA256FingerprintAsString(byte[] in) {
        byte[] res = CertTools.generateSHA256Fingerprint(in);
        return new String(Hex.encode((byte[])res));
    }

    public static byte[] generateSHA1Fingerprint(byte[] ba) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            return md.digest(ba);
        }
        catch (NoSuchAlgorithmException nsae) {
            log.error((Object)"SHA1 algorithm not supported", (Throwable)nsae);
            return null;
        }
    }

    public static byte[] generateSHA256Fingerprint(byte[] ba) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(ba);
        }
        catch (NoSuchAlgorithmException nsae) {
            log.error((Object)"SHA-256 algorithm not supported", (Throwable)nsae);
            return null;
        }
    }

    public static byte[] generateMD5Fingerprint(byte[] ba) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return md.digest(ba);
        }
        catch (NoSuchAlgorithmException nsae) {
            log.error((Object)"MD5 algorithm not supported", (Throwable)nsae);
            return null;
        }
    }

    public static int sunKeyUsageToBC(boolean[] sku) {
        if (sku == null) {
            return -1;
        }
        int bcku = 0;
        if (sku[0]) {
            bcku |= 0x80;
        }
        if (sku[1]) {
            bcku |= 0x40;
        }
        if (sku[2]) {
            bcku |= 0x20;
        }
        if (sku[3]) {
            bcku |= 0x10;
        }
        if (sku[4]) {
            bcku |= 8;
        }
        if (sku[5]) {
            bcku |= 4;
        }
        if (sku[6]) {
            bcku |= 2;
        }
        if (sku[7]) {
            bcku |= 1;
        }
        if (sku[8]) {
            bcku |= 0x8000;
        }
        return bcku;
    }

    public static String insertCNPostfix(String dn, String cnpostfix, X500NameStyle nameStyle) {
        if (log.isTraceEnabled()) {
            log.trace((Object)(">insertCNPostfix: dn=" + dn + ", cnpostfix=" + cnpostfix));
        }
        if (dn == null) {
            return null;
        }
        RDN[] rdns = IETFUtils.rDNsFromString((String)dn, (X500NameStyle)nameStyle);
        X500NameBuilder nameBuilder = new X500NameBuilder(nameStyle);
        boolean replaced = false;
        for (RDN rdn : rdns) {
            AttributeTypeAndValue[] attributeTypeAndValues;
            for (AttributeTypeAndValue atav : attributeTypeAndValues = rdn.getTypesAndValues()) {
                if (atav.getType() == null) continue;
                String currentSymbol = CeSecoreNameStyle.DefaultSymbols.get(atav.getType());
                if (!replaced && "CN".equals(currentSymbol)) {
                    nameBuilder.addRDN(atav.getType(), IETFUtils.valueToString((ASN1Encodable)atav.getValue()) + cnpostfix);
                    replaced = true;
                    continue;
                }
                nameBuilder.addRDN(atav);
            }
        }
        String ret = nameBuilder.build().toString();
        if (log.isTraceEnabled()) {
            log.trace((Object)("<reverseDN: " + ret));
        }
        return ret;
    }

    @Deprecated
    public static List<String> getX500NameComponents(String dn) {
        return DnComponents.getX500NameComponents(dn);
    }

    @Deprecated
    public static String getParentDN(String dn) {
        return DnComponents.getParentDN(dn);
    }

    @Deprecated
    public static List<ASN1ObjectIdentifier> getX509FieldOrder(boolean ldaporder) {
        return DnComponents.getX509FieldOrder(ldaporder);
    }

    public static String getOidFromString(String oidString) {
        String retval = oidString;
        Pattern pattern = Pattern.compile("[^0-9.]");
        Matcher matcher = pattern.matcher(oidString);
        if (matcher.find()) {
            int endIndex = matcher.start();
            if (endIndex == 0) {
                return null;
            }
            retval = oidString.substring(0, endIndex - 1);
        }
        return retval;
    }

    public static String getOidWildcardPattern(String oidWildcard) {
        String wildcardMatchPattern = oidWildcard.replaceAll("\\.", "\\\\.").replaceAll("\\*", "([0-9.]*)");
        return wildcardMatchPattern;
    }

    public static List<Certificate> createCertChain(Collection<?> certlistin) throws CertPathValidatorException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException {
        return CertTools.createCertChain(certlistin, new Date());
    }

    /*
     * Enabled force condition propagation
     * Lifted jumps to return sites
     */
    public static List<Certificate> createCertChain(Collection<?> certlistin, Date now) throws CertPathValidatorException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException {
        ArrayList<Certificate> returnval = new ArrayList<Certificate>();
        List<Certificate> certlist = CertTools.orderCertificateChain(certlistin);
        Certificate rootca = null;
        for (Certificate crt : certlist) {
            if (!CertTools.isSelfSigned(crt)) continue;
            rootca = crt;
        }
        if (rootca == null) {
            throw new CertPathValidatorException("No root CA certificate found in certificate list");
        }
        Certificate rootcert = null;
        ArrayList<Certificate> calist = new ArrayList<Certificate>();
        for (Certificate next : certlist) {
            if (CertTools.isSelfSigned(next)) {
                rootcert = next;
                continue;
            }
            calist.add(next);
        }
        if (calist.isEmpty()) {
            returnval.add(rootcert);
            return returnval;
        } else {
            Certificate test = (Certificate)calist.get(0);
            if (test.getType().equals("CVC")) {
                if (calist.size() != 1) throw new CertPathValidatorException("CVC certificate chain can not be of length longer than two.");
                returnval.add(test);
                returnval.add(rootcert);
                return returnval;
            } else {
                HashSet<TrustAnchor> trustancors = new HashSet<TrustAnchor>();
                TrustAnchor trustanchor = null;
                trustanchor = new TrustAnchor((X509Certificate)rootcert, null);
                trustancors.add(trustanchor);
                PKIXParameters params = new PKIXParameters(trustancors);
                params.setRevocationEnabled(false);
                params.setDate(now);
                CertPathValidator certPathValidator = CertPathValidator.getInstance(CertPathValidator.getDefaultType(), "BC");
                CertificateFactory fact = CertTools.getCertificateFactory();
                CertPath certpath = fact.generateCertPath(calist);
                CertPathValidatorResult result = certPathValidator.validate(certpath, params);
                PKIXCertPathValidatorResult pkixResult = (PKIXCertPathValidatorResult)result;
                returnval.addAll(certpath.getCertificates());
                TrustAnchor ta = pkixResult.getTrustAnchor();
                X509Certificate cert = ta.getTrustedCert();
                returnval.add(cert);
            }
        }
        return returnval;
    }

    private static List<Certificate> orderCertificateChain(Collection<?> certlist) throws CertPathValidatorException {
        int i;
        ArrayList<Certificate> returnval = new ArrayList<Certificate>();
        Certificate rootca = null;
        HashMap<String, Certificate> cacertmap = new HashMap<String, Certificate>();
        for (Object possibleCertificate : certlist) {
            Certificate cert = null;
            try {
                cert = (Certificate)possibleCertificate;
            }
            catch (ClassCastException e) {
                byte[] certBytes = (byte[])possibleCertificate;
                try {
                    cert = CertTools.getCertfromByteArray(certBytes);
                }
                catch (CertificateParsingException e1) {
                    throw new CertPathValidatorException(e1);
                }
            }
            if (CertTools.isSelfSigned(cert)) {
                rootca = cert;
                continue;
            }
            log.debug((Object)("Adding to cacertmap with index, issuerDn: '" + CertTools.getIssuerDN(cert) + "'"));
            cacertmap.put(CertTools.getIssuerDN(cert), cert);
        }
        if (rootca == null) {
            throw new CertPathValidatorException("No root CA certificate found in certificatelist");
        }
        returnval.add(0, rootca);
        Certificate currentcert = rootca;
        for (i = 0; certlist.size() != returnval.size() && i <= certlist.size(); ++i) {
            Certificate nextcert;
            if (log.isTraceEnabled()) {
                log.trace((Object)("Looking in cacertmap for '" + CertTools.getSubjectDN(currentcert) + "'"));
            }
            if ((nextcert = (Certificate)cacertmap.get(CertTools.getSubjectDN(currentcert))) == null) {
                if (log.isDebugEnabled()) {
                    log.debug((Object)"Dumping keys of CA certificate map:");
                    for (String issuerDn : cacertmap.keySet()) {
                        log.debug((Object)issuerDn);
                    }
                }
                throw new CertPathValidatorException("Error building certificate path. Could find certificate with SubjectDN " + CertTools.getSubjectDN(currentcert) + " in certificate map. See debug log for details.");
            }
            returnval.add(0, nextcert);
            currentcert = nextcert;
        }
        if (i > certlist.size()) {
            throw new CertPathValidatorException("Error building certificate path");
        }
        return returnval;
    }

    public static boolean compareCertificateChains(Certificate[] chainA, Certificate[] chainB) {
        if (chainA == null || chainB == null) {
            return false;
        }
        if (chainA.length != chainB.length) {
            return false;
        }
        for (int i = 0; i < chainA.length; ++i) {
            if (chainA[i] != null && chainA[i].equals(chainB[i])) continue;
            return false;
        }
        return true;
    }

    public static String dumpCertificateAsString(Certificate cert) {
        return CertificateImplementationRegistry.INSTANCE.getCertificateImplementation(cert.getType()).dumpCertificateAsString(cert);
    }

    public static PKCS10CertificationRequest getCertificateRequestFromPem(String pemEncodedCsr) {
        if (pemEncodedCsr == null) {
            return null;
        }
        PKCS10CertificationRequest csr = null;
        ByteArrayInputStream pemStream = new ByteArrayInputStream(pemEncodedCsr.getBytes(StandardCharsets.UTF_8));
        try (PEMParser pemParser = new PEMParser((Reader)new BufferedReader(new InputStreamReader(pemStream)));){
            Object parsedObj = pemParser.readObject();
            if (parsedObj instanceof PKCS10CertificationRequest) {
                csr = (PKCS10CertificationRequest)parsedObj;
            }
        }
        catch (IOException | DecoderException e) {
            log.info((Object)("IOException while decoding certificate request from PEM: " + e.getMessage()));
            log.debug((Object)"IOException while decoding certificate request from PEM.", e);
        }
        return csr;
    }

    public static PKCS10CertificationRequest genPKCS10CertificationRequest(String signatureAlgorithm, X500Name subject, PublicKey publickey, ASN1Set attributes, PrivateKey privateKey, String provider) throws OperatorCreationException {
        BufferingContentSigner signer;
        CertificationRequestInfo reqInfo;
        try {
            SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance((Object)publickey.getEncoded());
            reqInfo = new CertificationRequestInfo(subject, pkinfo, attributes);
            if (provider == null || "BC".equals(provider)) {
                provider = CryptoProviderTools.getProviderNameFromAlg(signatureAlgorithm);
            }
            signer = new BufferingContentSigner(new JcaContentSignerBuilder(signatureAlgorithm).setProvider(provider).build(privateKey), 20480);
            signer.getOutputStream().write(reqInfo.getEncoded("DER"));
            signer.getOutputStream().flush();
        }
        catch (IOException e) {
            throw new IllegalStateException("Unexpected IOException was caught.", e);
        }
        byte[] sig = signer.getSignature();
        DERBitString sigBits = new DERBitString(sig);
        CertificationRequest req = new CertificationRequest(reqInfo, signer.getAlgorithmIdentifier(), (ASN1BitString)sigBits);
        return new PKCS10CertificationRequest(req);
    }

    public static byte[] createCertsOnlyCMS(List<X509Certificate> x509CertificateChain) throws CertificateEncodingException, CMSException {
        if (log.isTraceEnabled()) {
            String subjectdn = x509CertificateChain != null && !x509CertificateChain.isEmpty() ? CertTools.getSubjectDN(x509CertificateChain.get(0)) : "null";
            log.trace((Object)("Creating a certs-only CMS for " + subjectdn));
        }
        List<JcaX509CertificateHolder> certList = CertTools.convertToX509CertificateHolder(x509CertificateChain);
        CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
        cmsSignedDataGenerator.addCertificates((Store)new CollectionStore(certList));
        CMSSignedData cmsSignedData = cmsSignedDataGenerator.generate((CMSTypedData)new CMSAbsentContent(), true);
        try {
            return cmsSignedData.getEncoded();
        }
        catch (IOException e) {
            throw new CMSException(e.getMessage());
        }
    }

    public static ContentVerifierProvider genContentVerifierProvider(PublicKey pubkey) throws OperatorCreationException {
        return new JcaContentVerifierProviderBuilder().setProvider(CryptoProviderTools.getProviderNameFromAlg(pubkey.getAlgorithm())).build(pubkey);
    }

    public static final List<X509Certificate> convertCertificateChainToX509Chain(Collection<Certificate> chain) throws ClassCastException {
        ArrayList<X509Certificate> ret = new ArrayList<X509Certificate>();
        for (Certificate certificate : chain) {
            ret.add((X509Certificate)certificate);
        }
        return ret;
    }

    public static final List<Certificate> convertCertificateChainToGenericChain(Collection<X509Certificate> chain) {
        ArrayList<Certificate> ret = new ArrayList<Certificate>();
        for (Certificate certificate : chain) {
            ret.add(certificate);
        }
        return ret;
    }

    public static final JcaX509CertificateHolder[] convertToX509CertificateHolder(X509Certificate[] certificateChain) throws CertificateEncodingException {
        JcaX509CertificateHolder[] certificateHolderChain = new JcaX509CertificateHolder[certificateChain.length];
        for (int i = 0; i < certificateChain.length; ++i) {
            certificateHolderChain[i] = new JcaX509CertificateHolder(certificateChain[i]);
        }
        return certificateHolderChain;
    }

    public static final List<JcaX509CertificateHolder> convertToX509CertificateHolder(List<X509Certificate> certificateChain) throws CertificateEncodingException {
        ArrayList<JcaX509CertificateHolder> certificateHolderChain = new ArrayList<JcaX509CertificateHolder>();
        for (X509Certificate certificate : certificateChain) {
            certificateHolderChain.add(new JcaX509CertificateHolder(certificate));
        }
        return certificateHolderChain;
    }

    public static final List<X509Certificate> convertToX509CertificateList(Collection<X509CertificateHolder> certificateHolderChain) throws CertificateException {
        ArrayList<X509Certificate> ret = new ArrayList<X509Certificate>();
        JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter();
        for (X509CertificateHolder certificateHolder : certificateHolderChain) {
            ret.add(jcaX509CertificateConverter.getCertificate(certificateHolder));
        }
        return ret;
    }

    public static final X509Certificate[] convertToX509CertificateArray(Collection<X509CertificateHolder> certificateHolderChain) throws CertificateException {
        return CertTools.convertToX509CertificateList(certificateHolderChain).toArray(new X509Certificate[0]);
    }

    public static final List<X509CRL> convertToX509CRLList(Collection<X509CRLHolder> crlHolders) throws CRLException {
        ArrayList<X509CRL> ret = new ArrayList<X509CRL>();
        JcaX509CRLConverter jcaX509CRLConverter = new JcaX509CRLConverter();
        for (X509CRLHolder crlHolder : crlHolders) {
            ret.add(jcaX509CRLConverter.getCRL(crlHolder));
        }
        return ret;
    }

    public static final String createPublicKeyFingerprint(PublicKey publicKey, String algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            digest.reset();
            digest.update(publicKey.getEncoded());
            String result = Hex.toHexString((byte[])digest.digest());
            if (log.isDebugEnabled()) {
                log.debug((Object)("Fingerprint " + result + " created for public key: " + new String(Base64.encode(publicKey.getEncoded()))));
            }
            return result;
        }
        catch (NoSuchAlgorithmException e) {
            log.warn((Object)"Could not create fingerprint for public key ", (Throwable)e);
            return null;
        }
    }

    public static List<X509Certificate> extractEndEntityCertificateFromKeyStore(byte[] keyStoreBytes, String keyStoreType, String keyStorePassword) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(new ByteArrayInputStream(keyStoreBytes), keyStorePassword.toCharArray());
        String alias = null;
        Iterator<String> aliases = keyStore.aliases().asIterator();
        while (aliases.hasNext()) {
            String currentAlias = aliases.next();
            if (currentAlias.equals("cacert")) continue;
            alias = currentAlias;
            break;
        }
        if (alias == null) {
            throw new IllegalStateException("Keystore does not have end entity certificate");
        }
        Certificate[] chain = KeyTools.getCertChain(keyStore, alias);
        if (chain == null) {
            throw new IllegalStateException("Certificate chain appears to be absent");
        }
        return Stream.of(chain).filter(X509Certificate.class::isInstance).map(X509Certificate.class::cast).collect(Collectors.toList());
    }

    @Deprecated
    public static String getCommonNameFromSubjectDn(String subjectDn) {
        return DnComponents.getCommonNameFromSubjectDn(subjectDn);
    }

    public static Collection<X509CertificateHolder> parseP7B(InputStream is) throws CMSException, IOException {
        InputStreamReader isr = new InputStreamReader(is);
        PEMParser parser = new PEMParser((Reader)isr);
        ContentInfo info = (ContentInfo)parser.readObject();
        CMSSignedData csd = new CMSSignedData(info);
        Store certstore = csd.getCertificates();
        Collection collection = certstore.getMatches(null);
        parser.close();
        return collection;
    }

    private static byte[] getFirstCertificate(Collection<X509CertificateHolder> collection) throws CertificateException {
        if (null != collection) {
            X509CertificateHolder certholder = collection.iterator().next();
            X509Certificate x509cert = new JcaX509CertificateConverter().getCertificate(certholder);
            return Base64.encode(x509cert.getEncoded());
        }
        return null;
    }

    public static byte[] getPKCS7Certificate(InputStream is) throws CertificateException, IOException, CMSException {
        InputStreamReader isr = new InputStreamReader(is);
        try (PEMParser parser = new PEMParser((Reader)isr);){
            ContentInfo info = (ContentInfo)parser.readObject();
            CMSSignedData csd = new CMSSignedData(info);
            byte[] byArray = csd.getEncoded();
            return byArray;
        }
    }

    public static String getPEMCertificate(Collection<X509CertificateHolder> collection) throws CertificateException {
        byte[] b64 = CertTools.getFirstCertificate(collection);
        return BEGIN_CERTIFICATE_WITH_NL + new String(b64) + "\n-----END CERTIFICATE-----";
    }

    public static String getPEMCertificate(byte[] bytes) {
        byte[] b64 = Base64.encode(bytes);
        return BEGIN_CERTIFICATE_WITH_NL + new String(b64) + "\n-----END CERTIFICATE-----";
    }

    public static String getPKCS7PEMCertificate(byte[] bytes) {
        byte[] b64 = Base64.encode(bytes);
        return "-----BEGIN PKCS7-----\n" + new String(b64) + "\n-----END PKCS7-----";
    }

    public static byte[] getFirstCertificateFromPKCS7(byte[] pkcs7) throws CMSException, IOException {
        byte[] firstCertificate = null;
        CMSSignedData csd = new CMSSignedData(pkcs7);
        Store certstore = csd.getCertificates();
        Collection collection = certstore.getMatches(null);
        Iterator ci = collection.iterator();
        if (ci.hasNext()) {
            firstCertificate = ((X509CertificateHolder)ci.next()).getEncoded();
        }
        return firstCertificate;
    }

    public static String encapsulateCsr(String csrBody) {
        if (csrBody == null) {
            return null;
        }
        if (!(csrBody = csrBody.replace(BEGIN_KEYTOOL_CERTIFICATE_REQUEST, BEGIN_CERTIFICATE_REQUEST).replace(END_KEYTOOL_CERTIFICATE_REQUEST, END_CERTIFICATE_REQUEST)).startsWith(BEGIN_CERTIFICATE_REQUEST) && org.apache.commons.codec.binary.Base64.isBase64((String)csrBody)) {
            return "-----BEGIN CERTIFICATE REQUEST-----\n" + csrBody + "\n-----END CERTIFICATE REQUEST-----";
        }
        return csrBody;
    }

    static {
        DnComponents.getDnObjects(true);
    }
}

