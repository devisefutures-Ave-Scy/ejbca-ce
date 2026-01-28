/*
 * Decompiled with CFR 0.152.
 */
package com.keyfactor.util.keys;

public class TaskWithSigningException
extends Exception {
    private static final long serialVersionUID = 1L;

    public TaskWithSigningException(String message) {
        super(message);
    }

    public TaskWithSigningException(String message, Exception cause) {
        super(message, cause);
    }
}

