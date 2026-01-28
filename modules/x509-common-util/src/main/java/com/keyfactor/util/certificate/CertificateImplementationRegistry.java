/*
 * Decompiled with CFR 0.152.
 */
package com.keyfactor.util.certificate;

import com.keyfactor.util.certificate.CertificateImplementation;
import com.keyfactor.util.certificate.x509.X509CertificateUtility;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;

public enum CertificateImplementationRegistry {
    INSTANCE;

    private final Map<String, CertificateImplementation> certificateImplementations = new HashMap<String, CertificateImplementation>();
    private final Map<Class<?>, CertificateImplementation> certificateImplementationsByClassType = new HashMap();

    private CertificateImplementationRegistry() {
        for (CertificateImplementation certificateImplementation : ServiceLoader.load(CertificateImplementation.class)) {
            this.addCertificateImplementation(certificateImplementation);
        }
        if (!this.certificateImplementationsByClassType.containsKey(X509Certificate.class)) {
            this.addCertificateImplementation(new X509CertificateUtility());
        }
    }

    public void addCertificateImplementation(CertificateImplementation certificateImplementation) {
        this.certificateImplementations.put(certificateImplementation.getType(), certificateImplementation);
        this.certificateImplementationsByClassType.put(certificateImplementation.getImplementationClass(), certificateImplementation);
    }

    public CertificateImplementation getCertificateImplementation(String name) {
        return this.certificateImplementations.get(name);
    }

    public CertificateImplementation getCertificateImplementation(Class<?> clazz) {
        return this.certificateImplementationsByClassType.get(clazz);
    }

    public <T extends Certificate> T getCertfromByteArray(byte[] cert, String provider, Class<T> returnType) throws CertificateParsingException {
        CertificateImplementation certificateImplementation;
        String prov = provider;
        if (provider == null) {
            prov = "BC";
        }
        if ((certificateImplementation = this.getCertificateImplementation(returnType)) != null) {
            return (T)((Certificate)returnType.cast(certificateImplementation.parseCertificate(provider, cert)));
        }
        if (this.certificateImplementations.size() != 0) {
            for (CertificateImplementation implementation : this.certificateImplementations.values()) {
                try {
                    return (T)((Certificate)returnType.cast(implementation.parseCertificate(prov, cert)));
                }
                catch (CertificateParsingException certificateParsingException) {
                }
            }
        } else {
            return (T)((Certificate)returnType.cast(new X509CertificateUtility().parseCertificate(provider, cert)));
        }
        throw new CertificateParsingException("No certificate could be parsed from byte array. See debug logs for details.");
    }
}

