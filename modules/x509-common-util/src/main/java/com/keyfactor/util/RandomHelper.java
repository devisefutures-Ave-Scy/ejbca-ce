/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.commons.lang.StringUtils
 *  org.apache.log4j.Logger
 *  org.bouncycastle.crypto.Digest
 *  org.bouncycastle.crypto.digests.SHA512Digest
 *  org.bouncycastle.crypto.prng.SP800SecureRandomBuilder
 *  org.bouncycastle.util.Strings
 */
package com.keyfactor.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.prng.SP800SecureRandomBuilder;
import org.bouncycastle.util.Strings;

public final class RandomHelper {
    private static final Logger log = Logger.getLogger(RandomHelper.class);
    private static Map<String, SecureRandom> randomInstances = new HashMap<String, SecureRandom>();

    private RandomHelper() {
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     * Enabled force condition propagation
     * Lifted jumps to return sites
     */
    public static SecureRandom getInstance(String algorithm) {
        SecureRandom randomInstance = randomInstances.get(algorithm);
        if (randomInstance != null) return randomInstance;
        Class<RandomHelper> clazz = RandomHelper.class;
        synchronized (RandomHelper.class) {
            randomInstance = randomInstances.get(algorithm);
            if (randomInstance != null) return randomInstance;
            randomInstance = RandomHelper.getSecureRandomFromAlgorithm(algorithm);
            randomInstances.put(algorithm, randomInstance);
            // ** MonitorExit[var2_2] (shouldn't be in output)
            return randomInstance;
        }
    }

    private static SecureRandom getSecureRandomFromAlgorithm(String algorithm) {
        SecureRandom random = null;
        try {
            if (StringUtils.equalsIgnoreCase((String)algorithm, (String)"BCSP800HYBRID")) {
                random = RandomHelper.createBCSP800Hybrid();
                log.info((Object)"Using FIPS/SP800 compliant Bouncy Castle Hybrid serialNumber RNG algorithm.");
            } else {
                if (StringUtils.equalsIgnoreCase((String)algorithm, (String)"defaultstrong")) {
                    throw new IllegalStateException("The algorithm option " + algorithm + " is not supported by this software. Please use a non-blocking algorithm instead.");
                }
                if (StringUtils.equalsIgnoreCase((String)algorithm, (String)"default")) {
                    random = new SecureRandom();
                    log.info((Object)("Using default " + random.getAlgorithm() + " serialNumber RNG algorithm."));
                } else if (!StringUtils.isEmpty((String)algorithm)) {
                    random = SecureRandom.getInstance(algorithm);
                    log.info((Object)("Using " + algorithm + " serialNumber RNG algorithm."));
                } else if (random == null) {
                    random = RandomHelper.createBCSP800Hybrid();
                    log.info((Object)"Using FIPS/SP800 compliant Bouncy Castle Hybrid serialNumber RNG algorithm.");
                }
            }
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm " + algorithm + " was not a valid algorithm.", e);
        }
        random.nextBytes(new byte[0]);
        return random;
    }

    private static SecureRandom createBCSP800Hybrid() throws NoSuchAlgorithmException {
        SecureRandom sourceRandom = SecureRandom.getInstanceStrong();
        return new SP800SecureRandomBuilder(sourceRandom, true).setPersonalizationString(Strings.toByteArray((String)"Bouncy Castle Hybrid Random")).buildHash((Digest)new SHA512Digest(), null, false);
    }
}

