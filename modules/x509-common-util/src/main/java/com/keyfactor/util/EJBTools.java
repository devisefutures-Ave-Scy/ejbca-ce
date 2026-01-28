/*
 * Decompiled with CFR 0.152.
 */
package com.keyfactor.util;

import com.keyfactor.util.CertificateSerializableWrapper;
import com.keyfactor.util.certificate.CertificateWrapper;
import com.keyfactor.util.keys.KeyPairWrapper;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public final class EJBTools {
    private EJBTools() {
    }

    public static CertificateWrapper wrap(Certificate cert) {
        if (cert == null) {
            return null;
        }
        return new CertificateSerializableWrapper(cert);
    }

    public static Certificate unwrap(CertificateWrapper certWrapper) {
        if (certWrapper == null) {
            return null;
        }
        return certWrapper.getCertificate();
    }

    public static List<CertificateWrapper> wrapCertCollection(Collection<Certificate> certs) {
        if (certs == null) {
            return null;
        }
        ArrayList<CertificateWrapper> list = new ArrayList<CertificateWrapper>(certs.size());
        for (Certificate cert : certs) {
            list.add(EJBTools.wrap(cert));
        }
        return list;
    }

    public static List<Certificate> unwrapCertCollection(Collection<CertificateWrapper> wrappedCerts) {
        if (wrappedCerts == null) {
            return null;
        }
        ArrayList<Certificate> list = new ArrayList<Certificate>(wrappedCerts.size());
        for (CertificateWrapper wrapped : wrappedCerts) {
            list.add(EJBTools.unwrap(wrapped));
        }
        return list;
    }

    public static KeyPairWrapper wrap(KeyPair keyPair) {
        if (keyPair == null) {
            return null;
        }
        return new KeyPairWrapper(keyPair);
    }

    public static KeyPair unwrap(KeyPairWrapper keyPairWrapper) {
        if (keyPairWrapper == null) {
            return null;
        }
        return keyPairWrapper.getKeyPair();
    }
}

