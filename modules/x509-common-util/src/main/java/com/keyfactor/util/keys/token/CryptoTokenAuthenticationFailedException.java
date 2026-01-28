/*
 * Decompiled with CFR 0.152.
 */
package com.keyfactor.util.keys.token;

import com.keyfactor.CesecoreException;

public class CryptoTokenAuthenticationFailedException
extends CesecoreException {
    private static final long serialVersionUID = -1444838755654213775L;

    public CryptoTokenAuthenticationFailedException() {
    }

    public CryptoTokenAuthenticationFailedException(String msg) {
        super(msg);
    }

    public CryptoTokenAuthenticationFailedException(String msg, Throwable cause) {
        super(msg, cause);
    }
}

