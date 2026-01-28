/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.bouncycastle.asn1.x509.AlgorithmIdentifier
 *  org.bouncycastle.cert.ocsp.RespID
 *  org.bouncycastle.operator.DigestCalculator
 */
package com.keyfactor.util;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.operator.DigestCalculator;

public class SHA1DigestCalculator
implements DigestCalculator {
    private ByteArrayOutputStream bOut = new ByteArrayOutputStream();
    private MessageDigest digest;

    public SHA1DigestCalculator(MessageDigest digest) {
        this.digest = digest;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return RespID.HASH_SHA1;
    }

    public OutputStream getOutputStream() {
        return this.bOut;
    }

    public byte[] getDigest() {
        byte[] bytes = this.digest.digest(this.bOut.toByteArray());
        this.bOut.reset();
        return bytes;
    }

    public static SHA1DigestCalculator buildSha1Instance() {
        try {
            return new SHA1DigestCalculator(MessageDigest.getInstance("SHA1"));
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}

