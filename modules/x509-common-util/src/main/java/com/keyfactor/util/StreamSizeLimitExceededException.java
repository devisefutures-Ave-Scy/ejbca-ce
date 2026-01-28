/*
 * Decompiled with CFR 0.152.
 */
package com.keyfactor.util;

import java.io.IOException;

public class StreamSizeLimitExceededException
extends IOException {
    private static final long serialVersionUID = 1L;

    public StreamSizeLimitExceededException() {
    }

    public StreamSizeLimitExceededException(String message) {
        super(message);
    }

    public StreamSizeLimitExceededException(String message, Throwable cause) {
        super(message, cause);
    }

    public StreamSizeLimitExceededException(Throwable cause) {
        super(cause);
    }
}

