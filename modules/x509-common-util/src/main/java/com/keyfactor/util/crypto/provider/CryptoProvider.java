/*
 * Decompiled with CFR 0.152.
 */
package com.keyfactor.util.crypto.provider;

import java.security.Provider;

public interface CryptoProvider {
    public Provider getProvider();

    public String getErrorMessage();

    public String getName();
}

