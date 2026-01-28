/*
 * Decompiled with CFR 0.152.
 */
package com.keyfactor.util.keys;

public class KeyUtilRuntimeException
extends RuntimeException {
    private static final long serialVersionUID = 1L;

    KeyUtilRuntimeException(String message, Exception cause) {
        super(message, cause);
    }

    KeyUtilRuntimeException(String message) {
        super(message);
    }
}

