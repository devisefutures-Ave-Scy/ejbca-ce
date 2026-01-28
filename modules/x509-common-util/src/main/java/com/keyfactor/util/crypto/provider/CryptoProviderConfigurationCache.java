/*
 * Decompiled with CFR 0.152.
 */
package com.keyfactor.util.crypto.provider;

public enum CryptoProviderConfigurationCache {
    INSTANCE;

    private boolean p11disableHashingSignMechanisms = true;
    private boolean keystoreCacheEnabled = true;
    private boolean permitExtractablePrivateKeys = false;

    public boolean isP11disableHashingSignMechanisms() {
        return this.p11disableHashingSignMechanisms;
    }

    public void setP11disableHashingSignMechanisms(boolean p11disableHashingSignMechanisms) {
        this.p11disableHashingSignMechanisms = p11disableHashingSignMechanisms;
    }

    public boolean isKeystoreCacheEnabled() {
        return this.keystoreCacheEnabled;
    }

    public void setKeystoreCacheEnabled(boolean keystoreCacheEnabled) {
        this.keystoreCacheEnabled = keystoreCacheEnabled;
    }

    @Deprecated(since="5.3.0")
    public boolean isPermitExtractablePrivateKeys() {
        return this.permitExtractablePrivateKeys;
    }

    @Deprecated(since="5.3.0")
    public void setPermitExtractablePrivateKeys(boolean permitExtractablePrivateKeys) {
        this.permitExtractablePrivateKeys = permitExtractablePrivateKeys;
    }
}

