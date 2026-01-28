/*
 * Decompiled with CFR 0.152.
 */
package com.keyfactor.util.crypto.provider;

import com.keyfactor.util.crypto.provider.CryptoProvider;
import java.util.HashSet;
import java.util.ServiceLoader;
import java.util.Set;

public enum CryptoProviderRegistry {
    INSTANCE;

    private Set<CryptoProvider> cryptoProviders = new HashSet<CryptoProvider>();

    private CryptoProviderRegistry() {
        for (CryptoProvider cryptoProvider : ServiceLoader.load(CryptoProvider.class)) {
            this.cryptoProviders.add(cryptoProvider);
        }
    }

    public Set<CryptoProvider> getCryptoProviders() {
        return this.cryptoProviders;
    }
}

