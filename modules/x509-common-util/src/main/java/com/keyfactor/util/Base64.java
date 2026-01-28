/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.commons.codec.binary.Base64
 *  org.bouncycastle.util.encoders.Base64
 */
package com.keyfactor.util;

import java.io.ByteArrayOutputStream;

public final class Base64 {
    private Base64() {
    }

    public static byte[] encode(byte[] data) {
        return encode(data, true);
    }

    public static byte[] encode(byte[] data, boolean splitlines) {
        byte[] bytes = org.bouncycastle.util.encoders.Base64.encode((byte[])data);
        if (splitlines) {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            for (int i = 0; i < bytes.length; i += 64) {
                if (i + 64 < bytes.length) {
                    os.write(bytes, i, 64);
                    os.write(10);
                    continue;
                }
                os.write(bytes, i, bytes.length - i);
            }
            bytes = os.toByteArray();
        }
        return bytes;
    }

    public static byte[] decodeURLSafe(String token) {
        return org.apache.commons.codec.binary.Base64.decodeBase64((byte[])token.getBytes());
    }

    public static byte[] decode(byte[] bytes) {
        return org.bouncycastle.util.encoders.Base64.decode((byte[])bytes);
    }
}

