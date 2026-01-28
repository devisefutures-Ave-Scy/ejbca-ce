/*
 * Decompiled with CFR 0.152.
 */
package com.keyfactor.util;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.certificate.CertificateWrapper;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;

final class CertificateSerializableWrapper
implements CertificateWrapper,
Serializable {
    private static final long serialVersionUID = 1L;
    private byte[] certificateBytes;
    private transient Certificate certificate = null;

    CertificateSerializableWrapper(Certificate certificate) {
        if (certificate == null) {
            throw new IllegalStateException("Can't wrap null certificate");
        }
        this.certificate = certificate;
        this.certificateBytes = null;
    }

    @Override
    public Certificate getCertificate() {
        if (this.certificate == null && this.certificateBytes != null) {
            try {
                this.certificate = CertTools.getCertfromByteArray(this.certificateBytes, Certificate.class);
            }
            catch (CertificateParsingException e) {
                throw new IllegalStateException(e);
            }
        }
        return this.certificate;
    }

    private void writeObject(ObjectOutputStream stream) throws IOException {
        if (this.certificateBytes == null) {
            try {
                this.certificateBytes = this.certificate.getEncoded();
            }
            catch (CertificateEncodingException e) {
                throw new IllegalStateException(e);
            }
        }
        stream.defaultWriteObject();
    }
}

