/*
 * Decompiled with CFR 0.152.
 */
package com.keyfactor.util.certificate;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.util.Date;

public interface CertificateImplementation {
    public String getType();

    public Class<?> getImplementationClass();

    public String getCertificateSignatureAlgorithm(Certificate var1);

    public String getSubjectDn(Certificate var1);

    public String getIssuerDn(Certificate var1);

    public BigInteger getSerialNumber(Certificate var1);

    public String getSerialNumberAsString(Certificate var1);

    public byte[] getSignature(Certificate var1);

    public Date getNotAfter(Certificate var1);

    public Date getNotBefore(Certificate var1);

    public Certificate parseCertificate(String var1, byte[] var2) throws CertificateParsingException;

    public boolean isCA(Certificate var1);

    public void checkValidity(Certificate var1, Date var2) throws CertificateExpiredException, CertificateNotYetValidException;

    public String dumpCertificateAsString(Certificate var1);
}

