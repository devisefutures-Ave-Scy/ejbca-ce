/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.log4j.Logger
 */
package com.keyfactor.util.keys;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Vector;
import java.util.concurrent.locks.ReentrantLock;
import javax.crypto.SecretKey;
import org.apache.log4j.Logger;

public class CachingKeyStoreWrapper {
    private static final Logger log = Logger.getLogger(CachingKeyStoreWrapper.class);
    private final ReentrantLock updateLock = new ReentrantLock(false);
    private final KeyStore keyStore;
    private final KeyStoreCache keyStoreCache;

    private static boolean isSunP11(KeyStore keyStore) {
        return keyStore.getProvider().getName().indexOf("SunPKCS11") == 0;
    }

    private String fixBadUTF8(String orig) {
        if (!CachingKeyStoreWrapper.isSunP11(this.keyStore)) {
            return orig;
        }
        byte[] bvIn = orig.getBytes(StandardCharsets.UTF_16BE);
        byte[] bvOut = new byte[bvIn.length / 2];
        for (int i = 1; i < bvIn.length; i += 2) {
            bvOut[i / 2] = (byte)(bvIn[i] & 0xFF);
        }
        return new String(bvOut, StandardCharsets.UTF_8);
    }

    private String makeBadUTF8(String orig) {
        if (!CachingKeyStoreWrapper.isSunP11(this.keyStore)) {
            return orig;
        }
        byte[] bvIn = orig.getBytes(StandardCharsets.UTF_8);
        byte[] bvOut = new byte[bvIn.length * 2];
        for (int i = 0; i < bvIn.length; ++i) {
            bvOut[i * 2] = 0;
            bvOut[i * 2 + 1] = (byte)(bvIn[i] & 0xFF);
        }
        return new String(bvOut, StandardCharsets.UTF_16BE);
    }

    @Deprecated
    public KeyStore getKeyStore() {
        return this.keyStore;
    }

    public CachingKeyStoreWrapper(KeyStore keyStore, boolean cachingEnabled) throws KeyStoreException {
        this.keyStore = keyStore;
        if (log.isDebugEnabled()) {
            log.debug((Object)("cachingEnabled: " + cachingEnabled));
        }
        this.keyStoreCache = cachingEnabled ? new KeyStoreCache(keyStore) : null;
    }

    public Certificate getCertificate(String alias) throws KeyStoreException {
        if (this.keyStoreCache == null) {
            return this.keyStore.getCertificate(alias);
        }
        KeyStoreMapEntry keyStoreMapEntry = this.keyStoreCache.get(alias);
        if (keyStoreMapEntry == null) {
            return null;
        }
        if (keyStoreMapEntry.certificateChain == null || keyStoreMapEntry.certificateChain.length == 0) {
            return null;
        }
        return keyStoreMapEntry.certificateChain[0];
    }

    public void setCertificateEntry(String alias, Certificate certificate) throws KeyStoreException {
        this.keyStore.setCertificateEntry(alias, certificate);
        if (this.keyStoreCache == null) {
            return;
        }
        this.updateLock.lock();
        try {
            this.keyStoreCache.addEntry(alias, new KeyStoreMapEntry(certificate));
        }
        finally {
            this.updateLock.unlock();
        }
        if (log.isDebugEnabled()) {
            log.debug((Object)("Updated certificate entry in cache for alias: " + alias));
        }
    }

    public Enumeration<String> aliases() throws KeyStoreException {
        if (this.keyStoreCache == null) {
            return this.keyStore.aliases();
        }
        return this.keyStoreCache.getAliases();
    }

    public void store(OutputStream outputStream, char[] password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        this.keyStore.store(outputStream, password);
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public void setKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        this.keyStore.setKeyEntry(alias, key, password, chain);
        if (this.keyStoreCache == null) {
            return;
        }
        this.updateLock.lock();
        try {
            KeyStoreMapEntry keyStoreMapEntry = new KeyStoreMapEntry(chain, key);
            this.keyStoreCache.addEntry(alias, keyStoreMapEntry);
        }
        finally {
            this.updateLock.unlock();
        }
        if (log.isDebugEnabled()) {
            log.debug((Object)("Updated key entry in cache for alias: " + alias));
        }
    }

    public void deleteEntry(String alias) throws KeyStoreException {
        this.keyStore.deleteEntry(this.makeBadUTF8(alias));
        if (this.keyStoreCache == null) {
            return;
        }
        this.updateLock.lock();
        try {
            this.keyStoreCache.removeEntry(alias);
        }
        finally {
            this.updateLock.unlock();
        }
        if (log.isDebugEnabled()) {
            log.debug((Object)("Removed entry from cache for alias: " + alias));
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public KeyStore.Entry getEntry(String alias, KeyStore.ProtectionParameter protParam) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
        if (this.keyStoreCache == null) {
            return this.keyStore.getEntry(alias, protParam);
        }
        KeyStoreMapEntry keyStoreMapEntry = this.keyStoreCache.get(alias);
        if (keyStoreMapEntry == null) {
            return null;
        }
        if (keyStoreMapEntry.isTrusted || keyStoreMapEntry.key != null) {
            return keyStoreMapEntry.getEntry();
        }
        this.updateLock.lock();
        try {
            KeyStoreMapEntry afterWaitEntry = this.keyStoreCache.get(alias);
            if (afterWaitEntry.isTrusted || afterWaitEntry.key != null) {
                KeyStore.Entry entry = afterWaitEntry.getEntry();
                return entry;
            }
            KeyStoreMapEntry newEntry = new KeyStoreMapEntry(alias, protParam, this.keyStore);
            this.keyStoreCache.addEntry(alias, newEntry);
            KeyStore.Entry entry = newEntry.getEntry();
            return entry;
        }
        finally {
            this.updateLock.unlock();
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public void setEntry(String alias, KeyStore.Entry entry, KeyStore.ProtectionParameter protParam) throws KeyStoreException {
        this.keyStore.setEntry(alias, entry, protParam);
        if (this.keyStoreCache == null) {
            return;
        }
        this.updateLock.lock();
        try {
            KeyStoreMapEntry keyStoreMapEntry = new KeyStoreMapEntry(entry);
            this.keyStoreCache.addEntry(alias, keyStoreMapEntry);
        }
        finally {
            this.updateLock.unlock();
        }
    }

    public Provider getProvider() {
        return this.keyStore.getProvider();
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public Key getKey(String alias, char[] password) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        if (this.keyStoreCache == null) {
            return this.keyStore.getKey(alias, password);
        }
        KeyStoreMapEntry keyStoreMapEntry = this.keyStoreCache.get(alias);
        if (keyStoreMapEntry == null) {
            return null;
        }
        if (keyStoreMapEntry.isTrusted || keyStoreMapEntry.key != null) {
            return keyStoreMapEntry.key;
        }
        this.updateLock.lock();
        try {
            KeyStoreMapEntry entryAfterWait = this.keyStoreCache.get(alias);
            if (entryAfterWait.isTrusted || entryAfterWait.key != null) {
                Key key = entryAfterWait.key;
                return key;
            }
            KeyStoreMapEntry newEntry = new KeyStoreMapEntry(alias, this.keyStore, password, entryAfterWait);
            this.keyStoreCache.addEntry(alias, newEntry);
            if (log.isDebugEnabled()) {
                log.debug((Object)("Caching key for alias: " + alias));
            }
            Key key = newEntry.key;
            return key;
        }
        finally {
            this.updateLock.unlock();
        }
    }

    public boolean isKeyEntry(String alias) throws KeyStoreException {
        if (this.keyStoreCache == null) {
            return this.keyStore.isKeyEntry(alias);
        }
        KeyStoreMapEntry keyStoreMapEntry = this.keyStoreCache.get(alias);
        return keyStoreMapEntry != null && !keyStoreMapEntry.isTrusted;
    }

    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        if (this.keyStoreCache == null) {
            return this.keyStore.getCertificateChain(alias);
        }
        KeyStoreMapEntry entry = this.keyStoreCache.get(alias);
        return entry != null ? entry.certificateChain : null;
    }

    private class KeyStoreCache {
        private HashMap<String, KeyStoreMapEntry> cache = new HashMap();

        public KeyStoreCache(KeyStore keyStore) throws KeyStoreException {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                this.cache.put(CachingKeyStoreWrapper.this.fixBadUTF8(alias), new KeyStoreMapEntry(alias, keyStore));
                if (!log.isDebugEnabled()) continue;
                log.debug((Object)("KeyStore has alias: " + alias));
            }
        }

        public void addEntry(String alias, KeyStoreMapEntry newEntry) {
            HashMap<String, KeyStoreMapEntry> clone = new HashMap<String, KeyStoreMapEntry>(this.cache);
            clone.put(alias, newEntry);
            this.cache = clone;
        }

        public void removeEntry(String alias) {
            HashMap<String, KeyStoreMapEntry> clone = new HashMap<String, KeyStoreMapEntry>(this.cache);
            clone.remove(alias);
            this.cache = clone;
        }

        public KeyStoreMapEntry get(String alias) {
            return this.cache.get(alias);
        }

        public Enumeration<String> getAliases() {
            return new Vector<String>(this.cache.keySet()).elements();
        }
    }

    private class KeyStoreMapEntry {
        public final Key key;
        public final Certificate[] certificateChain;
        public final boolean isTrusted;

        public KeyStoreMapEntry(String alias, KeyStore keyStore) throws KeyStoreException {
            Key tmpKey;
            if (keyStore.isCertificateEntry(alias)) {
                Certificate certificate = keyStore.getCertificate(alias);
                this.certificateChain = new Certificate[]{certificate};
                this.key = null;
                this.isTrusted = true;
                return;
            }
            this.isTrusted = false;
            this.certificateChain = keyStore.getCertificateChain(alias);
            try {
                tmpKey = keyStore.getKey(alias, null);
            }
            catch (KeyStoreException e) {
                throw e;
            }
            catch (Exception e) {
                tmpKey = null;
            }
            this.key = tmpKey;
        }

        public KeyStoreMapEntry(String alias, KeyStore keyStore, char[] password, KeyStoreMapEntry oldEntry) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
            assert (!oldEntry.isTrusted);
            this.isTrusted = false;
            this.certificateChain = oldEntry.certificateChain;
            this.key = keyStore.getKey(alias, password);
        }

        public KeyStoreMapEntry(Certificate certificate) {
            this.key = null;
            this.isTrusted = true;
            this.certificateChain = new Certificate[]{certificate};
        }

        public KeyStoreMapEntry(Certificate[] chain, Key k) {
            this.key = k;
            this.isTrusted = false;
            this.certificateChain = chain;
        }

        public KeyStoreMapEntry(String alias, KeyStore.ProtectionParameter protection, KeyStore keyStore) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
            this(keyStore.getEntry(alias, protection));
        }

        public KeyStoreMapEntry(KeyStore.Entry entry) {
            if (entry instanceof KeyStore.PrivateKeyEntry) {
                this.key = ((KeyStore.PrivateKeyEntry)entry).getPrivateKey();
                this.certificateChain = ((KeyStore.PrivateKeyEntry)entry).getCertificateChain();
                this.isTrusted = false;
                return;
            }
            if (entry instanceof KeyStore.SecretKeyEntry) {
                this.key = ((KeyStore.SecretKeyEntry)entry).getSecretKey();
                this.certificateChain = null;
                this.isTrusted = false;
                return;
            }
            if (entry instanceof KeyStore.TrustedCertificateEntry) {
                this.key = null;
                this.certificateChain = new Certificate[]{((KeyStore.TrustedCertificateEntry)entry).getTrustedCertificate()};
                this.isTrusted = true;
                return;
            }
            throw new Error("It should not be possible to reach this point!");
        }

        public KeyStore.Entry getEntry() {
            if (this.isTrusted) {
                assert (this.certificateChain != null);
                assert (this.certificateChain.length == 1);
                return new KeyStore.TrustedCertificateEntry(this.certificateChain[0]);
            }
            assert (this.key != null);
            if (this.certificateChain != null) {
                return new KeyStore.PrivateKeyEntry((PrivateKey)this.key, this.certificateChain);
            }
            return new KeyStore.SecretKeyEntry((SecretKey)this.key);
        }
    }
}

