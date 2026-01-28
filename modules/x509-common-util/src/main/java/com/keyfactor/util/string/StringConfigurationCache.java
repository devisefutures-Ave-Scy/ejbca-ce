/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.commons.lang3.ArrayUtils
 */
package com.keyfactor.util.string;

import com.keyfactor.util.StringTools;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import org.apache.commons.lang3.ArrayUtils;

public enum StringConfigurationCache {
    INSTANCE;

    public static final int DEFAULT_ENCRYPTION_COUNT = 100;
    private static final char[] DEFAULT_FORBIDDEN_CHARACTERS;
    private Set<Character> forbiddenCharacters = null;
    private int passwordEncryptionCount = 100;
    private char[] encryptionKey = new char[0];

    public void setForbiddenCharacters(char[] forbiddenCharacters) {
        this.forbiddenCharacters = forbiddenCharacters == null ? new HashSet<Character>(Arrays.asList(ArrayUtils.toObject((char[])DEFAULT_FORBIDDEN_CHARACTERS))) : new HashSet<Character>(Arrays.asList(ArrayUtils.toObject((char[])forbiddenCharacters)));
        StringTools.CharSet.reset();
    }

    public char[] getForbiddenCharacters() {
        if (this.forbiddenCharacters == null) {
            return DEFAULT_FORBIDDEN_CHARACTERS;
        }
        return ArrayUtils.toPrimitive((Character[])this.forbiddenCharacters.toArray(new Character[this.forbiddenCharacters.size()]));
    }

    public int getPasswordEncryptionCount() {
        return this.passwordEncryptionCount;
    }

    public void setPasswordEncryptionCount(int passwordEncryptionCount) {
        this.passwordEncryptionCount = passwordEncryptionCount;
    }

    public char[] getEncryptionKey() {
        return this.encryptionKey;
    }

    public void setEncryptionKey(char[] encryptionKey) {
        this.encryptionKey = encryptionKey;
    }

    public boolean useLegacyEncryption() {
        String defaultPassword = StringTools.deobfuscate("OBF:1m0r1kmo1ioe1ia01j8z17y41l0q1abo1abm1abg1abe1kyc17ya1j631i5y1ik01kjy1lxf");
        return Objects.deepEquals(defaultPassword.toCharArray(), this.encryptionKey);
    }

    static {
        DEFAULT_FORBIDDEN_CHARACTERS = new char[]{'\n', '\r', ';', '!', '\u0000', '%', '`', '?', '$', '~'};
    }
}

