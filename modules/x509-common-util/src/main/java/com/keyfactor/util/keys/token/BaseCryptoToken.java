/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.commons.lang.StringUtils
 *  org.apache.log4j.Logger
 *  org.bouncycastle.jce.ECKeyUtil
 *  org.bouncycastle.util.encoders.Hex
 */
package com.keyfactor.util.keys.token;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.crypto.provider.CryptoProviderConfigurationCache;
import com.keyfactor.util.keys.CachingKeyStoreWrapper;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.string.StringConfigurationCache;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.util.encoders.Hex;

public abstract class BaseCryptoToken
implements CryptoToken {
    private static final long serialVersionUID = 2133644669863292622L;
    private static final Logger log = Logger.getLogger(BaseCryptoToken.class);
    private String mJcaProviderName = null;
    private String mJceProviderName = null;
    private char[] mAuthCode;
    private Properties properties;
    private int id;
    protected transient CachingKeyStoreWrapper keyStore;

    protected void setKeyStore(KeyStore keystore) throws KeyStoreException {
        this.keyStore = keystore == null ? null : new CachingKeyStoreWrapper(keystore, CryptoProviderConfigurationCache.INSTANCE.isKeystoreCacheEnabled());
    }

    protected CachingKeyStoreWrapper getKeyStore() throws CryptoTokenOfflineException {
        this.autoActivate();
        if (this.keyStore == null) {
            String msg = "The keys in the crypto token with id " + this.id + " could not be accessed. Is the crypto token active? ";
            throw new CryptoTokenOfflineException(msg);
        }
        return this.keyStore;
    }

    protected void autoActivate() {
        if (this.mAuthCode != null && this.keyStore == null) {
            try {
                if (log.isDebugEnabled()) {
                    log.debug((Object)"Trying to autoactivate CryptoToken");
                }
                this.activate(this.mAuthCode);
            }
            catch (Exception e) {
                log.debug((Object)e);
            }
        }
    }

    @Override
    public boolean doPermitExtractablePrivateKey() {
        return this.getProperties().containsKey("allow.extractable.privatekey") && Boolean.parseBoolean(this.getProperties().getProperty("allow.extractable.privatekey"));
    }

    public abstract boolean permitExtractablePrivateKeyForTest();

    @Override
    public void testKeyPair(String alias) throws InvalidKeyException, CryptoTokenOfflineException {
        PrivateKey privateKey = this.getPrivateKey(alias);
        PublicKey publicKey = this.getPublicKey(alias);
        this.testKeyPair(alias, publicKey, privateKey);
    }

    @Override
    public void testKeyPair(String alias, PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {
        try {
            long keyUsageDecrypt = 261L;
            long keyUsageSign = 264L;
            Set<Long> keyUsageSet = new HashSet();
            keyUsageSet = this.getKeyUsagesFromPrivateKey(alias);
            boolean encryptOnlyKeyPair = keyUsageSet.contains(261L) && !keyUsageSet.contains(264L);
            this.assertNonExtractable(alias, privateKey);
            if (log.isDebugEnabled()) {
                log.debug((Object)("Testing key '" + alias + "'on crypto token '" + this.getTokenName() + "' (SHA1: " + CertTools.getFingerprintAsString(publicKey.getEncoded()) + ")."));
                if (encryptOnlyKeyPair) {
                    log.debug((Object)("The key '" + alias + "'on crypto token '" + this.getTokenName() + "' will be tested for encrypt/decrypt operations using the provider '" + this.getEncProviderName() + "'."));
                } else {
                    log.debug((Object)("The key '" + alias + "'on crypto token '" + this.getTokenName() + "' will be tested  for sign/verify operations  using the provider '" + this.getSignProviderName() + "'."));
                }
            }
            if (encryptOnlyKeyPair) {
                KeyTools.testEncryptionDecryptionKeys(publicKey, privateKey, this.getEncProviderName());
            } else {
                KeyTools.testKey(privateKey, publicKey, this.getSignProviderName());
            }
        }
        catch (CryptoTokenOfflineException e) {
            throw new IllegalStateException(e);
        }
    }

    private void assertNonExtractable(String alias, PrivateKey privateKey) throws InvalidKeyException {
        if (!this.permitExtractablePrivateKeyForTest() && KeyTools.isPrivateKeyExtractable(privateKey)) {
            throw new InvalidKeyException("PKCS#11 key with alias " + alias + "in crypto token " + this.getTokenName() + " is marked as extractable. This is poor security practice and is not permitted.");
        }
    }

    @Override
    public void keyAuthorizeInit(String alias, KeyPair kakKeyPair, String signProviderName, String selectedPaddingScheme) throws CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Operation not supported for this Crypto Token type");
    }

    @Override
    public void keyAuthorize(String alias, KeyPair kakPair, String signProviderName, long maxOperationCount, String selectedPaddingScheme) throws CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Operation not supported for this Crypto Token type");
    }

    @Override
    public void changeAuthData(String alias, KeyPair currentKakPair, KeyPair newKakPair, String signProviderName, String selectedPaddingScheme) throws CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Operation not supported for this Crypto Token type");
    }

    @Override
    public boolean isKeyInitialized(String alias) {
        return true;
    }

    @Override
    public long maxOperationCount(String alias) {
        return Long.MAX_VALUE;
    }

    @Override
    public void backupKey(int keySpecId, Path backupFilePath) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Operation not supported for this Crypto Token type");
    }

    @Override
    public void restoreKey(int keySpecId, Path backupFilePath) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Operation not supported for this Crypto Token type");
    }

    protected PublicKey readPublicKey(String alias, boolean warn) throws KeyStoreException, CryptoTokenOfflineException {
        try {
            Certificate cert = this.getKeyStore().getCertificate(alias);
            PublicKey pubk = null;
            if (cert != null) {
                pubk = cert.getPublicKey();
            } else if (warn) {
                String msg = "Can not read public key certificate with alias '" + alias + "' from Crypto Token, got null. If the key of the certificate was generated after the latest application server start then restart the application server.";
                log.warn((Object)msg);
                if (log.isDebugEnabled()) {
                    Enumeration<String> en = this.getKeyStore().aliases();
                    while (en.hasMoreElements()) {
                        log.debug((Object)("Existing alias: " + en.nextElement()));
                    }
                }
            }
            return pubk;
        }
        catch (ProviderException e) {
            throw new CryptoTokenOfflineException((Throwable)e);
        }
    }

    protected void init(Properties properties, boolean doAutoActivate, int id) {
        if (log.isDebugEnabled()) {
            log.debug((Object)(">init: doAutoActivate=" + doAutoActivate));
        }
        this.id = id;
        this.setProperties(properties);
        if (doAutoActivate) {
            this.autoActivate();
        }
        if (log.isDebugEnabled()) {
            log.debug((Object)("<init: doAutoActivate=" + doAutoActivate));
        }
    }

    @Override
    public int getId() {
        return this.id;
    }

    public void setId(int id) {
        this.id = id;
    }

    @Override
    public String getTokenName() {
        return this.properties.getProperty("tokenName");
    }

    @Override
    public void setTokenName(String tokenName) {
        if (this.properties == null) {
            this.properties = new Properties();
        }
        this.properties.setProperty("tokenName", tokenName);
    }

    @Override
    public Properties getProperties() {
        return this.properties;
    }

    @Override
    public void setProperties(Properties properties) {
        if (properties == null) {
            this.properties = new Properties();
        } else {
            if (log.isDebugEnabled()) {
                if (properties.containsKey("pin") || properties.containsKey("PIN")) {
                    Properties prop = new Properties();
                    prop.putAll((Map<?, ?>)properties);
                    if (properties.containsKey("pin")) {
                        prop.setProperty("pin", "hidden");
                    }
                    if (properties.containsKey("PIN")) {
                        prop.setProperty("PIN", "hidden");
                    }
                    log.debug((Object)("Prop: " + prop.toString()));
                } else {
                    log.debug((Object)("Properties: " + properties.toString()));
                }
            }
            this.properties = properties;
            String authCode = BaseCryptoToken.getAutoActivatePin(properties);
            this.mAuthCode = authCode == null ? null : authCode.toCharArray();
        }
    }

    public static String getAutoActivatePin(Properties properties) {
        String pin = properties.getProperty("pin");
        if (pin != null) {
            return StringTools.passwordDecryption(pin, "autoactivation pin");
        }
        if (log.isDebugEnabled()) {
            log.debug((Object)"Not using autoactivation pin");
        }
        return null;
    }

    public static String setAutoActivatePin(Properties properties, String pin, boolean encrypt) {
        String ret = null;
        if (StringUtils.isNotEmpty((String)pin)) {
            String authcode = pin;
            if (encrypt) {
                char[] encryptionKey = StringConfigurationCache.INSTANCE.getEncryptionKey();
                authcode = StringTools.pbeEncryptStringWithSha256Aes192(pin, encryptionKey, StringConfigurationCache.INSTANCE.useLegacyEncryption());
            }
            if (properties != null) {
                properties.setProperty("pin", authcode);
            }
            ret = "pin " + authcode;
        }
        return ret;
    }

    protected void setProviders(String jcaProviderClassName, String jceProviderClassName) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        Provider jcaProvider;
        String errorMessage = "Failed to initialize JCE provider. Encryption operations may not work but we are continuing...";
        try {
            jcaProvider = (Provider)Class.forName(jcaProviderClassName).getConstructor(new Class[0]).newInstance(new Object[0]);
        }
        catch (ClassNotFoundException | IllegalAccessException | IllegalArgumentException | NoSuchMethodException | SecurityException | InvocationTargetException e) {
            log.error((Object)"Failed to initialize JCE provider. Encryption operations may not work but we are continuing...", (Throwable)e);
            throw new IllegalStateException("Failed to initialize JCE provider. Encryption operations may not work but we are continuing...", e);
        }
        this.setProvider(jcaProvider);
        this.mJcaProviderName = jcaProvider.getName();
        if (jceProviderClassName != null) {
            try {
                Provider jceProvider = (Provider)Class.forName(jceProviderClassName).getConstructor(new Class[0]).newInstance(new Object[0]);
                this.setProvider(jceProvider);
                this.mJceProviderName = jceProvider.getName();
            }
            catch (Exception e) {
                log.error((Object)"Failed to initialize JCE provider. Encryption operations may not work but we are continuing...", (Throwable)e);
            }
        } else {
            this.mJceProviderName = null;
        }
    }

    @Override
    public void storeKey(String alias, Key key, Certificate[] chain, char[] password) throws KeyStoreException {
        this.keyStore.deleteEntry(alias);
        this.keyStore.setKeyEntry(alias, key, password, chain);
    }

    protected void setJCAProvider(Provider prov) {
        this.setProvider(prov);
        this.mJcaProviderName = prov != null ? prov.getName() : null;
    }

    protected void setJCAProviderName(String pName) {
        this.mJcaProviderName = pName;
    }

    private void setProvider(Provider prov) {
        if (prov != null) {
            String pName = prov.getName();
            if (pName.startsWith("LunaJCA")) {
                prov.put("Alg.Alias.Cipher.RSA/NONE/NoPadding", "RSA//NoPadding");
                prov.put("Alg.Alias.Cipher.1.2.840.113549.1.1.1", "RSA//NoPadding");
                prov.put("Alg.Alias.Cipher.RSA/ECB/PKCS1Padding", "RSA//PKCS1v1_5");
                prov.put("Alg.Alias.Cipher.1.2.840.113549.3.7", "DES3/CBC/PKCS5Padding");
            }
            if (Security.getProvider(pName) == null) {
                log.info((Object)("Adding Provider from BaseCryptoToken: " + pName));
                Security.addProvider(prov);
            }
            if (Security.getProvider(pName) == null) {
                throw new ProviderException("Not possible to install provider from BaseCryptoToken: " + pName);
            }
        } else if (log.isDebugEnabled()) {
            log.debug((Object)"No provider passed to setProvider()");
        }
    }

    @Override
    public String getSignProviderName() {
        return this.mJcaProviderName;
    }

    @Override
    public String getEncProviderName() {
        if (this.mJceProviderName == null) {
            return this.mJcaProviderName;
        }
        return this.mJceProviderName;
    }

    @Override
    public boolean isAliasUsed(String alias) {
        boolean aliasInUse = false;
        try {
            this.getPublicKey(alias, false);
            aliasInUse = true;
        }
        catch (CryptoTokenOfflineException e) {
            try {
                this.getPrivateKey(alias, false);
                aliasInUse = true;
            }
            catch (CryptoTokenOfflineException e2) {
                try {
                    this.getKey(alias, false);
                    aliasInUse = true;
                }
                catch (CryptoTokenOfflineException cryptoTokenOfflineException) {
                    // empty catch block
                }
            }
        }
        return aliasInUse;
    }

    @Override
    public PrivateKey getPrivateKey(String alias) throws CryptoTokenOfflineException {
        return this.getPrivateKey(alias, true);
    }

    private PrivateKey getPrivateKey(String alias, boolean warn) throws CryptoTokenOfflineException {
        try {
            PrivateKey privateK = (PrivateKey)this.getKeyStore().getKey(alias, this.mAuthCode != null && this.mAuthCode.length > 0 ? this.mAuthCode : null);
            if (privateK == null) {
                String msg;
                if (warn) {
                    msg = "Can not read private key with alias '" + alias + "' from Crypto Token, got null. If the key was generated after the latest application server start then restart the application server.";
                    log.warn((Object)msg);
                    if (log.isDebugEnabled()) {
                        Enumeration<String> aliases = this.getKeyStore().aliases();
                        while (aliases.hasMoreElements()) {
                            log.debug((Object)("Existing alias: " + aliases.nextElement()));
                        }
                    }
                }
                msg = "No key with alias '" + alias + "'.";
                throw new CryptoTokenOfflineException(msg);
            }
            return privateK;
        }
        catch (KeyStoreException e) {
            throw new CryptoTokenOfflineException((Throwable)e);
        }
        catch (UnrecoverableKeyException e) {
            throw new CryptoTokenOfflineException((Throwable)e);
        }
        catch (NoSuchAlgorithmException e) {
            throw new CryptoTokenOfflineException((Throwable)e);
        }
        catch (ProviderException e) {
            throw new CryptoTokenOfflineException((Throwable)e);
        }
    }

    @Override
    public boolean doesPrivateKeyExist(String alias) {
        try {
            return this.getPrivateKey(alias) != null;
        }
        catch (CryptoTokenOfflineException e) {
            return false;
        }
    }

    @Override
    public PublicKey getPublicKey(String alias) throws CryptoTokenOfflineException {
        return this.getPublicKey(alias, true);
    }

    private PublicKey getPublicKey(String alias, boolean warn) throws CryptoTokenOfflineException {
        try {
            PublicKey publicK = this.readPublicKey(alias, warn);
            if (publicK == null) {
                String msg = "No key with alias '" + alias + "'.";
                throw new CryptoTokenOfflineException(msg);
            }
            String str = this.getProperties().getProperty("explicit.ecc.publickey.parameters");
            boolean explicitEccParameters = Boolean.parseBoolean(str);
            if (explicitEccParameters && publicK.getAlgorithm().startsWith("EC")) {
                if (log.isDebugEnabled()) {
                    log.debug((Object)"Using explicit parameter encoding for ECC key.");
                }
                publicK = ECKeyUtil.publicToExplicitParameters((PublicKey)publicK, (String)"BC");
            }
            return publicK;
        }
        catch (KeyStoreException e) {
            throw new CryptoTokenOfflineException((Throwable)e);
        }
        catch (NoSuchProviderException e) {
            throw new CryptoTokenOfflineException((Throwable)e);
        }
        catch (IllegalArgumentException e) {
            throw new CryptoTokenOfflineException((Throwable)e);
        }
        catch (NoSuchAlgorithmException e) {
            throw new CryptoTokenOfflineException((Throwable)e);
        }
    }

    @Override
    public Key getKey(String alias) throws CryptoTokenOfflineException {
        return this.getKey(alias, true);
    }

    private Key getKey(String alias, boolean warn) throws CryptoTokenOfflineException {
        try {
            Key key = this.getKeyStore().getKey(alias, this.mAuthCode != null && this.mAuthCode.length > 0 ? this.mAuthCode : null);
            if (key == null && (key = this.getKeyFromProperties(alias)) == null) {
                String msg;
                if (warn) {
                    msg = "No key with alias '" + alias + "'.";
                    log.warn((Object)msg);
                    if (log.isDebugEnabled()) {
                        Enumeration<String> aliases = this.getKeyStore().aliases();
                        while (aliases.hasMoreElements()) {
                            log.debug((Object)("Existing alias: " + aliases.nextElement()));
                        }
                    }
                }
                msg = "No key with alias '" + alias + "'.";
                throw new CryptoTokenOfflineException(msg);
            }
            return key;
        }
        catch (KeyStoreException e) {
            throw new CryptoTokenOfflineException((Throwable)e);
        }
        catch (UnrecoverableKeyException e) {
            throw new CryptoTokenOfflineException((Throwable)e);
        }
        catch (NoSuchAlgorithmException e) {
            throw new CryptoTokenOfflineException((Throwable)e);
        }
        catch (ProviderException e) {
            throw new CryptoTokenOfflineException((Throwable)e);
        }
    }

    private Key getKeyFromProperties(String alias) {
        Key key = null;
        Properties prop = this.getProperties();
        String str = prop.getProperty(alias);
        if (StringUtils.isNotEmpty((String)str)) {
            try {
                PrivateKey privK = this.getPrivateKey("symwrap");
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", this.getEncProviderName());
                cipher.init(4, privK);
                byte[] bytes = Hex.decode((String)str);
                key = cipher.unwrap(bytes, "AES", 3);
            }
            catch (CryptoTokenOfflineException e) {
                log.debug((Object)e);
            }
            catch (NoSuchAlgorithmException e) {
                log.debug((Object)e);
            }
            catch (NoSuchProviderException e) {
                log.debug((Object)e);
            }
            catch (NoSuchPaddingException e) {
                log.debug((Object)e);
            }
            catch (InvalidKeyException e) {
                log.debug((Object)e);
            }
        }
        return key;
    }

    @Override
    public void reset() {
    }

    @Override
    public int getTokenStatus() {
        int ret = 2;
        try {
            this.getKeyStore();
            ret = 1;
        }
        catch (CryptoTokenOfflineException cryptoTokenOfflineException) {
            // empty catch block
        }
        return ret;
    }

    @Override
    public List<String> getAliases() throws KeyStoreException, CryptoTokenOfflineException {
        return Collections.list(this.getKeyStore().aliases());
    }

    @Override
    public boolean isAutoActivationPinPresent() {
        return BaseCryptoToken.getAutoActivatePin(this.getProperties()) != null;
    }
}

