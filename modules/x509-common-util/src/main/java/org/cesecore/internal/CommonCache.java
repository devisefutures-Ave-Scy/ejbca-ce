/*
 * Decompiled with CFR 0.152.
 */
package org.cesecore.internal;

import java.util.List;
import java.util.Map;

public interface CommonCache<T> {
    public T getEntry(Integer var1);

    public T getEntry(int var1);

    public boolean shouldCheckForUpdates(int var1);

    public void updateWith(int var1, int var2, String var3, T var4);

    public boolean willUpdate(int var1, int var2);

    public void removeEntry(int var1);

    public String getName(int var1);

    public Map<String, Integer> getNameToIdMap();

    public void flush();

    public void replaceCacheWith(List<Integer> var1);
}

