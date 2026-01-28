/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.log4j.Logger
 */
package org.cesecore.internal;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.log4j.Logger;
import org.cesecore.internal.CommonCache;

public abstract class CommonCacheBase<T>
implements CommonCache<T> {
    private static final Logger log = Logger.getLogger(CommonCacheBase.class);
    protected Map<Integer, CacheEntry> cache = new HashMap<Integer, CacheEntry>();
    protected Map<String, Integer> nameToIdMap = new HashMap<String, Integer>();

    protected abstract long getCacheTime();

    protected abstract long getMaxCacheLifeTime();

    @Override
    public T getEntry(Integer id) {
        CacheEntry cacheEntry = this.getCacheEntry(id);
        if (cacheEntry == null) {
            return null;
        }
        return cacheEntry.object;
    }

    @Override
    public T getEntry(int id) {
        return this.getEntry((Integer)id);
    }

    public Set<T> getAllEntries() {
        HashSet result = new HashSet();
        for (CacheEntry cacheEntry : this.cache.values()) {
            result.add(cacheEntry.object);
        }
        return result;
    }

    public Set<String> getAllNames() {
        HashSet<String> result = new HashSet<String>();
        for (CacheEntry cacheEntry : this.cache.values()) {
            result.add(cacheEntry.name);
        }
        return result;
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    public boolean shouldCheckForUpdates(int id) {
        long now = System.currentTimeMillis();
        long cacheTime = this.getCacheTime();
        if (cacheTime < 0L) {
            return true;
        }
        Integer key = id;
        CacheEntry cacheEntry = this.cache.get(key);
        if (cacheEntry == null) {
            return true;
        }
        if (cacheEntry.lastUpdate + cacheTime < now) {
            CacheEntry cacheEntry2 = cacheEntry;
            synchronized (cacheEntry2) {
                if (cacheEntry.lastUpdate + cacheTime < now) {
                    cacheEntry.lastUpdate = now;
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public void removeEntry(int id) {
        this.updateWith(id, 0, null, null);
    }

    @Override
    public boolean willUpdate(int id, int digest) {
        CacheEntry cacheEntry = this.getCacheEntry(id);
        if (cacheEntry == null || cacheEntry.digest != digest) {
            return true;
        }
        if (log.isDebugEnabled()) {
            log.debug((Object)("Update not needed " + cacheEntry.object.getClass().getSimpleName() + " in cache. Digest was " + digest + ", cacheEntry digest was " + cacheEntry.digest));
        }
        return false;
    }

    @Override
    public void updateWith(int id, int digest, String name, T object) {
        Integer key = id;
        if (name == null || object == null || this.getCacheTime() < 0L) {
            this.setCacheEntry(key, null);
        } else if (this.willUpdate(id, digest)) {
            CacheEntry cacheEntry = this.getCacheEntry(key);
            CacheEntry newCacheEntry = new CacheEntry(System.currentTimeMillis(), digest, name, object);
            this.setCacheEntry(key, newCacheEntry);
            if (log.isDebugEnabled()) {
                log.debug((Object)("Updated " + object.getClass().getSimpleName() + " cache. Digest was " + digest + ", cacheEntry digest was " + (Serializable)(cacheEntry == null ? "null" : Integer.valueOf(cacheEntry.digest))));
            }
        }
    }

    @Override
    public String getName(int id) {
        CacheEntry entry = this.getCacheEntry(id);
        return entry != null ? entry.name : null;
    }

    private CacheEntry getCacheEntry(Integer key) {
        return this.cache.get(key);
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private void setCacheEntry(Integer key, CacheEntry cacheEntry) {
        HashMap<Integer, CacheEntry> cacheStage = new HashMap<Integer, CacheEntry>();
        HashMap<String, Integer> nameToIdMapStage = new HashMap<String, Integer>();
        long maxCacheLifeTime = this.getMaxCacheLifeTime();
        long staleCutOffTime = System.currentTimeMillis() - maxCacheLifeTime;
        CommonCacheBase commonCacheBase = this;
        synchronized (commonCacheBase) {
            for (Map.Entry<Integer, CacheEntry> entry : this.cache.entrySet()) {
                Integer currentId = entry.getKey();
                if (key.equals(currentId)) continue;
                CacheEntry currentCacheEntry = entry.getValue();
                if (maxCacheLifeTime >= 1L && currentCacheEntry.lastUpdate < staleCutOffTime) continue;
                cacheStage.put(entry.getKey(), currentCacheEntry);
                nameToIdMapStage.put(currentCacheEntry.name, entry.getKey());
            }
            if (cacheEntry != null) {
                cacheStage.put(key, cacheEntry);
                nameToIdMapStage.put(cacheEntry.name, key);
            }
            this.cache = cacheStage;
            this.nameToIdMap = Collections.unmodifiableMap(nameToIdMapStage);
        }
    }

    @Override
    public Map<String, Integer> getNameToIdMap() {
        return this.nameToIdMap;
    }

    @Override
    public void flush() {
        HashMap<Integer, CacheEntry> cacheStage = new HashMap<Integer, CacheEntry>();
        HashMap<String, Integer> nameToIdMapStage = new HashMap<String, Integer>();
        this.replaceCache(cacheStage, nameToIdMapStage);
    }

    @Override
    public void replaceCacheWith(List<Integer> keys) {
        HashMap<Integer, CacheEntry> cacheStage = new HashMap<Integer, CacheEntry>();
        HashMap<String, Integer> nameToIdMapStage = new HashMap<String, Integer>();
        for (Integer key : keys) {
            CacheEntry entry = this.cache.get(key);
            cacheStage.put(key, entry);
            String name = entry.name;
            nameToIdMapStage.put(name, this.nameToIdMap.get(name));
        }
        this.replaceCache(cacheStage, nameToIdMapStage);
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private void replaceCache(Map<Integer, CacheEntry> cacheStage, Map<String, Integer> nameToIdMapStage) {
        CommonCacheBase commonCacheBase = this;
        synchronized (commonCacheBase) {
            this.cache = cacheStage;
            this.nameToIdMap = nameToIdMapStage;
        }
    }

    private class CacheEntry {
        long lastUpdate;
        final int digest;
        final String name;
        final T object;

        CacheEntry(long lastUpdate, int digest, String name, T object) {
            this.lastUpdate = lastUpdate;
            this.digest = digest;
            this.name = name;
            this.object = object;
        }
    }
}

