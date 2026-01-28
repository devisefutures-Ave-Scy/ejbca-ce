/*
 * Decompiled with CFR 0.152.
 */
package com.keyfactor.util.keys.token;

import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.KeyGenParams;
import java.io.IOException;
import java.io.Serializable;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public interface CryptoToken
extends Serializable {
    public static final int STATUS_ACTIVE = 1;
    public static final int STATUS_OFFLINE = 2;
    public static final String AUTOACTIVATE_PIN_PROPERTY = "pin";
    public static final String ALLOW_EXTRACTABLE_PRIVATE_KEY = "allow.extractable.privatekey";
    public static final String KEYPLACEHOLDERS_PROPERTY = "statedump.keytemplates";
    public static final String KEYPLACEHOLDERS_OUTER_SEPARATOR = "|";
    public static final String KEYPLACEHOLDERS_INNER_SEPARATOR = ";";
    public static final String EXPLICIT_ECC_PUBLICKEY_PARAMETERS = "explicit.ecc.publickey.parameters";
    public static final String TOKENNAME_PROPERTY = "tokenName";
    public static final String ALLOW_NONEXISTING_SLOT_PROPERTY = "allow.nonexisting.slot";
    public static final String KAK_ASSOCIATION_PREFIX = "KAK_";

    public void init(Properties var1, byte[] var2, int var3) throws Exception;

    public int getId();

    public void activate(char[] var1) throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException;

    public void deactivate();

    public boolean isAliasUsed(String var1);

    public PrivateKey getPrivateKey(String var1) throws CryptoTokenOfflineException;

    public boolean doesPrivateKeyExist(String var1);

    public PublicKey getPublicKey(String var1) throws CryptoTokenOfflineException;

    public Key getKey(String var1) throws CryptoTokenOfflineException;

    public void deleteEntry(String var1) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, CryptoTokenOfflineException;

    public void keyAuthorizeInit(String var1, KeyPair var2, String var3, String var4) throws CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException;

    public void keyAuthorize(String var1, KeyPair var2, String var3, long var4, String var6) throws CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException;

    public void changeAuthData(String var1, KeyPair var2, KeyPair var3, String var4, String var5) throws CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException;

    public void backupKey(int var1, Path var2) throws CryptoTokenOfflineException;

    public void restoreKey(int var1, Path var2) throws CryptoTokenOfflineException;

    public boolean isKeyInitialized(String var1);

    public long maxOperationCount(String var1);

    public void generateKeyPair(String var1, String var2) throws InvalidAlgorithmParameterException, CryptoTokenOfflineException;

    public void generateKeyPair(KeyGenParams var1, String var2) throws InvalidAlgorithmParameterException, CryptoTokenOfflineException;

    public void generateKeyPair(AlgorithmParameterSpec var1, String var2) throws InvalidAlgorithmParameterException, CertificateException, IOException, CryptoTokenOfflineException;

    public void generateKey(String var1, int var2, String var3) throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException, SignatureException, CertificateException, IOException, NoSuchPaddingException, IllegalBlockSizeException;

    public String getSignProviderName();

    public String getEncProviderName();

    public void reset();

    public String getTokenName();

    public void setTokenName(String var1);

    public int getTokenStatus();

    public Properties getProperties();

    public void setProperties(Properties var1);

    public void storeKey(String var1, Key var2, Certificate[] var3, char[] var4) throws KeyStoreException;

    public byte[] getTokenData();

    public void testKeyPair(String var1) throws InvalidKeyException, CryptoTokenOfflineException;

    public void testKeyPair(String var1, PublicKey var2, PrivateKey var3) throws InvalidKeyException;

    public boolean doPermitExtractablePrivateKey();

    public List<String> getAliases() throws KeyStoreException, CryptoTokenOfflineException;

    public boolean isAutoActivationPinPresent();

    public Set<Long> getKeyUsagesFromKey(String var1, boolean var2, long ... var3) throws CryptoTokenOfflineException;

    public Set<Long> getKeyUsagesFromPrivateKey(String var1) throws CryptoTokenOfflineException;

    public Set<Long> getKeyUsagesFromPublicKey(String var1) throws CryptoTokenOfflineException;
}

