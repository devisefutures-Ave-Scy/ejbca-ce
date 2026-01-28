/*
 * Decompiled with CFR 0.152.
 */
package com.keyfactor.util.keys.token;

import com.keyfactor.CesecoreException;
import com.keyfactor.ErrorCode;

public class CryptoTokenOfflineException
extends CesecoreException {
    private static final long serialVersionUID = -4228966531990184850L;

    public CryptoTokenOfflineException() {
        super.setErrorCode(ErrorCode.CA_OFFLINE);
    }

    public CryptoTokenOfflineException(String msg) {
        super(ErrorCode.CA_OFFLINE, msg);
    }

    public CryptoTokenOfflineException(Throwable e) {
        super(ErrorCode.CA_OFFLINE, e);
    }

    public CryptoTokenOfflineException(String msg, Throwable e) {
        super(ErrorCode.CA_OFFLINE, msg, e);
    }
}

