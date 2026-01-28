/*
 * Decompiled with CFR 0.152.
 */
package com.keyfactor.util.keys;

import java.util.HashMap;
import java.util.Map;

public enum KeyStoreCipher {
    PKCS12_3DES_3DES("PKCS12-3DES-3DES"),
    PKCS12_AES256_AES128("PKCS12-AES256-AES128");

    private static final Map<String, KeyStoreCipher> lookupMap;
    private final String label;

    private KeyStoreCipher(String label) {
        this.label = label;
    }

    public String getLabel() {
        return this.label;
    }

    public static KeyStoreCipher fromLabel(String label) {
        return lookupMap.get(label);
    }

    static {
        lookupMap = new HashMap<String, KeyStoreCipher>();
        for (KeyStoreCipher keyStoreCipher : KeyStoreCipher.values()) {
            lookupMap.put(keyStoreCipher.getLabel(), keyStoreCipher);
        }
    }
}

