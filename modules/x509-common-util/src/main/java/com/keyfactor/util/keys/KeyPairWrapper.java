/*
 * Decompiled with CFR 0.152.
 */
package com.keyfactor.util.keys;

import java.io.Serializable;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class KeyPairWrapper
implements Serializable {
    private static final long serialVersionUID = 1L;
    final byte[] encodedPublicKey;
    final byte[] encodedPrivateKey;
    final String algorithm;
    transient KeyPair cachedKeyPair = null;

    public KeyPairWrapper(KeyPair keyPair) {
        this.encodedPublicKey = keyPair.getPublic().getEncoded();
        this.encodedPrivateKey = keyPair.getPrivate().getEncoded();
        this.algorithm = keyPair.getPublic().getAlgorithm();
    }

    private PublicKey getPublicKey() {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(this.algorithm, "BC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(this.encodedPublicKey);
            return keyFactory.generatePublic(keySpec);
        }
        catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle was not a known provider.", e);
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm " + this.algorithm + " was not known at deserialisation", e);
        }
        catch (InvalidKeySpecException e) {
            throw new IllegalStateException("The incorrect key specification was implemented.", e);
        }
    }

    private PrivateKey getPrivateKey() {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(this.algorithm, "BC");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(this.encodedPrivateKey);
            return keyFactory.generatePrivate(keySpec);
        }
        catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle was not a known provider.", e);
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm " + this.algorithm + " was not known at deserialisation", e);
        }
        catch (InvalidKeySpecException e) {
            throw new IllegalStateException("The incorrect key specification was implemented.", e);
        }
    }

    public KeyPair getKeyPair() {
        if (this.cachedKeyPair == null) {
            this.cachedKeyPair = new KeyPair(this.getPublicKey(), this.getPrivateKey());
        }
        return this.cachedKeyPair;
    }
}

