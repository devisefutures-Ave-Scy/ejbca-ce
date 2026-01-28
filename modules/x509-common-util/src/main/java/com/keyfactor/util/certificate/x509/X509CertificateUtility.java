/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.log4j.Logger
 *  org.bouncycastle.asn1.x500.X500Name
 *  org.bouncycastle.asn1.x500.X500NameStyle
 */
package com.keyfactor.util.certificate.x509;

import com.keyfactor.util.CeSecoreNameStyle;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.SecurityFilterInputStream;
import com.keyfactor.util.certificate.CertificateImplementation;
import com.keyfactor.util.certificate.DnComponents;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;

public class X509CertificateUtility
implements CertificateImplementation {
    private static final Logger log = Logger.getLogger(X509CertificateUtility.class);

    @Override
    public String getType() {
        return "X.509";
    }

    @Override
    public Class<?> getImplementationClass() {
        return X509Certificate.class;
    }

    @Override
    public String getCertificateSignatureAlgorithm(Certificate certificate) {
        X509Certificate x509cert = (X509Certificate)certificate;
        String certSignatureAlgorithm = x509cert.getSigAlgName();
        if (log.isDebugEnabled()) {
            log.debug((Object)("certSignatureAlgorithm is: " + certSignatureAlgorithm));
        }
        return certSignatureAlgorithm;
    }

    @Override
    public String getSubjectDn(Certificate certificate) {
        X509Certificate x509cert;
        String clazz = certificate.getClass().getName();
        if (clazz.contains("org.bouncycastle")) {
            x509cert = (X509Certificate)certificate;
        } else {
            CertificateFactory cf = CertTools.getCertificateFactory();
            try {
                x509cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
            }
            catch (CertificateException e) {
                log.info((Object)("Could not get DN from X509Certificate. " + e.getMessage()));
                log.debug((Object)"", (Throwable)e);
                return null;
            }
        }
        X500Name dn = X500Name.getInstance((X500NameStyle)CeSecoreNameStyle.INSTANCE, (Object)x509cert.getSubjectX500Principal().getEncoded());
        return DnComponents.stringToBCDNString(dn.toString());
    }

    @Override
    public String getIssuerDn(Certificate certificate) {
        X509Certificate x509cert;
        String clazz = certificate.getClass().getName();
        if (clazz.contains("org.bouncycastle")) {
            x509cert = (X509Certificate)certificate;
        } else {
            CertificateFactory cf = CertTools.getCertificateFactory();
            try {
                x509cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
            }
            catch (CertificateException e) {
                log.info((Object)("Could not get DN from X509Certificate. " + e.getMessage()));
                log.debug((Object)"", (Throwable)e);
                return null;
            }
        }
        X500Name dn = X500Name.getInstance((X500NameStyle)CeSecoreNameStyle.INSTANCE, (Object)x509cert.getIssuerX500Principal().getEncoded());
        return DnComponents.stringToBCDNString(dn.toString());
    }

    @Override
    public BigInteger getSerialNumber(Certificate certificate) {
        X509Certificate xcert = (X509Certificate)certificate;
        return xcert.getSerialNumber();
    }

    @Override
    public String getSerialNumberAsString(Certificate certificate) {
        X509Certificate xcert = (X509Certificate)certificate;
        return xcert.getSerialNumber().toString(16).toUpperCase();
    }

    @Override
    public byte[] getSignature(Certificate certificate) {
        X509Certificate xcert = (X509Certificate)certificate;
        return xcert.getSignature();
    }

    @Override
    public Date getNotAfter(Certificate certificate) {
        X509Certificate xcert = (X509Certificate)certificate;
        return xcert.getNotAfter();
    }

    @Override
    public Date getNotBefore(Certificate certificate) {
        X509Certificate xcert = (X509Certificate)certificate;
        return xcert.getNotBefore();
    }

    @Override
    public Certificate parseCertificate(String provider, byte[] cert) throws CertificateParsingException {
        X509Certificate result;
        CertificateFactory cf = CertTools.getCertificateFactory(provider);
        try {
            result = (X509Certificate)cf.generateCertificate(new SecurityFilterInputStream(new ByteArrayInputStream(cert)));
        }
        catch (CertificateException e) {
            throw new CertificateParsingException("Could not parse byte array as X509Certificate." + e.getCause().getMessage(), e);
        }
        if (result != null) {
            return result;
        }
        throw new CertificateParsingException("Could not parse byte array as X509Certificate.");
    }

    @Override
    public boolean isCA(Certificate certificate) {
        X509Certificate x509cert = (X509Certificate)certificate;
        return x509cert.getBasicConstraints() > -1;
    }

    @Override
    public void checkValidity(Certificate certificate, Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        X509Certificate xcert = (X509Certificate)certificate;
        xcert.checkValidity(date);
    }

    @Override
    public String dumpCertificateAsString(Certificate certificate) {
        try {
            Certificate c = this.parseCertificate("BC", certificate.getEncoded());
            return c.toString();
        }
        catch (CertificateException e) {
            return e.getMessage();
        }
    }
}

