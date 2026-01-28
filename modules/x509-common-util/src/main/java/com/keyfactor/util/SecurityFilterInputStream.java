/*
 * Decompiled with CFR 0.152.
 */
package com.keyfactor.util;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

public class SecurityFilterInputStream
extends FilterInputStream {
    private long currentLength = 0L;
    private long maxBytes = 1048575L;
    public static final long DEFAULT_MAX_BYTES = 1048575L;

    public SecurityFilterInputStream(InputStream inputStream) {
        super(inputStream);
    }

    public SecurityFilterInputStream(InputStream inputStream, long maxBytes) {
        super(inputStream);
        this.maxBytes = maxBytes;
    }

    @Override
    public int read() throws IOException {
        int val = super.read();
        if (val != -1) {
            ++this.currentLength;
            this.checkLength();
        }
        return val;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int val = super.read(b, off, len);
        if (val > 0) {
            this.currentLength += (long)val;
            this.checkLength();
        }
        return val;
    }

    private void checkLength() {
        if (this.currentLength > this.maxBytes) {
            throw new SecurityException("Security violation: attempt to deserialize too many bytes from stream. Limit is " + this.maxBytes);
        }
    }

    public long getMaxBytes() {
        return this.maxBytes;
    }

    public void setMaxBytes(long maxBytes) {
        this.maxBytes = maxBytes;
    }
}

