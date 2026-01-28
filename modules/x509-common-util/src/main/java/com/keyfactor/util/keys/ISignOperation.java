/*
 * Decompiled with CFR 0.152.
 */
package com.keyfactor.util.keys;

import com.keyfactor.util.keys.TaskWithSigningException;
import java.security.Provider;

public interface ISignOperation {
    public void taskWithSigning(String var1, Provider var2) throws TaskWithSigningException;
}

