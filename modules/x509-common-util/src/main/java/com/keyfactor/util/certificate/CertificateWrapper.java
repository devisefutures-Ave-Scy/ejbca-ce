/*
 * Decompiled with CFR 0.152.
 */
package com.keyfactor.util.certificate;

import java.io.Serializable;
import java.security.cert.Certificate;

public interface CertificateWrapper
extends Serializable {
    public Certificate getCertificate();
}

