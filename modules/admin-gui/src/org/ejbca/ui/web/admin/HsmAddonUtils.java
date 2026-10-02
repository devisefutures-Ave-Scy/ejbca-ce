package org.ejbca.ui.web.admin;

import com.keyfactor.util.keys.token.BaseCryptoToken;

import java.security.PublicKey;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

public static final String SM_ADDON_PROBE_CLASS = "com.devisefutures.sm.HsmSmCryptoToken";

public final class HsmAddonUtils {

    private HsmAddonUtils() {}

    /**
     * Returns true if the add-on identified by the probe class is
     * installed and accessible in the current classloader.
     *
     * Typical probe classes:
     *   "com.devisefutures.ed25519.HsmEd25519CryptoToken"
     *   "com.devisefutures.sm.HsmSmCryptoToken"
     */
    public static boolean isAddonAvailable(String probeClass) {
        try {
            Thread.currentThread().getContextClassLoader()
                  .loadClass(probeClass);
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    /**
     * Returns true if simpleClassName is a CryptoToken implementation
     * from any installed HSM add-on (com.devisefutures.*).
     *
     * Used in type checks like isP11SlotType() to avoid hardcoding
     * add-on class names in EJBCA source.
     */
    public static boolean isHsmAddonToken(String simpleClassName) {
        if (simpleClassName == null || simpleClassName.isEmpty()) {
            return false;
        }
        // Static check — works regardless of classloader visibility
        if ("HsmEd25519CryptoToken".equals(simpleClassName) ||
                "HsmSmCryptoToken".equals(simpleClassName)) {
            return true;
        }
        // Dynamic check — works if the add-on is visible to the context classloader
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        for (String pkg : new String[]{
                "com.devisefutures.ed25519.",
                "com.devisefutures.sm."}) {
            try {
                Class<?> cls = cl.loadClass(pkg + simpleClassName);
                if (BaseCryptoToken.class.isAssignableFrom(cls)) {
                    return true;
                }
            } catch (ClassNotFoundException ignored) {}
        }
        return false;
    }

    public static boolean isSm2Key(final PublicKey pk) {
        if (pk == null) {
            return false;
        }
        if ("SM2".equalsIgnoreCase(pk.getAlgorithm())) {
            return true;
        }
        try {
            final SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(pk.getEncoded());
            return GMObjectIdentifiers.sm2p256v1.equals(spki.getAlgorithm().getAlgorithm())
                    || GMObjectIdentifiers.sm2p256v1.equals(spki.getAlgorithm().getParameters());            
        } catch (Exception e) {
            return false;
        }
    }    
}