/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.log4j.Logger
 *  org.bouncycastle.asn1.x500.X500Name
 *  org.bouncycastle.asn1.x500.X500NameStyle
 *  org.bouncycastle.asn1.x509.X509Name
 *  org.bouncycastle.jce.provider.BouncyCastleProvider
 *  org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
 */
package com.keyfactor.util;

import com.keyfactor.util.CeSecoreNameStyle;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.crypto.provider.CryptoProvider;
import com.keyfactor.util.crypto.provider.CryptoProviderRegistry;
import com.keyfactor.util.keys.KeyTools;
import java.security.Provider;
import java.security.Security;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

public final class CryptoProviderTools {
    private static final Logger log = Logger.getLogger(CryptoProviderTools.class);
    public static String SYSTEM_SECURITY_PROVIDER = "SUN";

    private CryptoProviderTools() {
    }

    public static boolean isUsingExportableCryptography() {
        return KeyTools.isUsingExportableCryptography();
    }

    public static synchronized void installBCProviderIfNotAvailable() {
        if (Security.getProvider("BC") == null) {
            CryptoProviderTools.installBCProvider();
        }
    }

    public static synchronized void removeBCProvider() {
        Security.removeProvider("BC");
        Security.removeProvider(BouncyCastlePQCProvider.PROVIDER_NAME);
        for (CryptoProvider provider : CryptoProviderRegistry.INSTANCE.getCryptoProviders()) {
            Security.removeProvider(provider.getName());
        }
    }

    public static synchronized void installBCProvider() {
        if (Security.addProvider((Provider)new BouncyCastlePQCProvider()) < 0) {
            log.debug((Object)"Cannot install BC PQC provider again!");
        }
        Security.addProvider((Provider)new BouncyCastleProvider());
        for (CryptoProvider provider : CryptoProviderRegistry.INSTANCE.getCryptoProviders()) {
            try {
                Security.addProvider(provider.getProvider());
            }
            catch (Exception e) {
                log.info((Object)provider.getErrorMessage(), (Throwable)e);
            }
        }
        X509Name.DefaultSymbols.put(X509Name.SN, "SN");
        X500Name.setDefaultStyle((X500NameStyle)CeSecoreNameStyle.INSTANCE);
        Provider p = Security.getProvider(SYSTEM_SECURITY_PROVIDER);
        if (p == null) {
            log.debug((Object)"SUN security provider does not exist, using BC as system default provider.");
            SYSTEM_SECURITY_PROVIDER = "BC";
        }
    }

    public static String getProviderNameFromAlg(String alg) {
        if (AlgorithmTools.isNonStandardPQC(alg)) {
            return BouncyCastlePQCProvider.PROVIDER_NAME;
        }
        return "BC";
    }
}

