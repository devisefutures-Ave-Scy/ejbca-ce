/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.log4j.Logger
 */
package com.keyfactor.util.keys;

import com.keyfactor.util.keys.ISignOperation;
import com.keyfactor.util.keys.TaskWithSigningException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import org.apache.log4j.Logger;

public class SignWithWorkingAlgorithm {
    private static final Logger log = Logger.getLogger(SignWithWorkingAlgorithm.class);
    private static final Map<Integer, SignWithWorkingAlgorithm> instanceMap = new HashMap<Integer, SignWithWorkingAlgorithm>();
    private final Provider provider;
    private final List<String> availableSignAlgorithms;
    private String signAlgorithm;
    private final Lock lock;

    public static boolean doSignTask(List<String> availableSignAlgorithms, String sProvider, ISignOperation operation) throws NoSuchProviderException, TaskWithSigningException {
        Provider provider = Security.getProvider(sProvider);
        if (provider == null) {
            throw new NoSuchProviderException();
        }
        return SignWithWorkingAlgorithm.doSignTask(availableSignAlgorithms, provider, operation);
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public static boolean doSignTask(List<String> availableSignAlgorithms, Provider provider, ISignOperation operation) throws TaskWithSigningException {
        SignWithWorkingAlgorithm instance;
        Integer mapKey = availableSignAlgorithms.hashCode() ^ provider.hashCode();
        Map<Integer, SignWithWorkingAlgorithm> map = instanceMap;
        synchronized (map) {
            SignWithWorkingAlgorithm waitInstance = instanceMap.get(mapKey);
            if (waitInstance == null) {
                instance = new SignWithWorkingAlgorithm(provider, availableSignAlgorithms);
                instanceMap.put(mapKey, instance);
            } else {
                instance = waitInstance;
            }
        }
        return instance.tryOutWorkingAlgorithm(operation);
    }

    private SignWithWorkingAlgorithm(Provider provider, List<String> availableSignAlgorithms) {
        this.provider = provider;
        this.lock = new ReentrantLock();
        this.availableSignAlgorithms = availableSignAlgorithms;
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private boolean tryOutWorkingAlgorithm(ISignOperation operation) throws TaskWithSigningException {
        if (this.signAlgorithm != null) {
            operation.taskWithSigning(this.signAlgorithm, this.provider);
            return true;
        }
        this.lock.lock();
        try {
            if (this.signAlgorithm != null) {
                operation.taskWithSigning(this.signAlgorithm, this.provider);
                boolean bl = true;
                return bl;
            }
            for (String trySignAlgorithm : this.availableSignAlgorithms) {
                try {
                    operation.taskWithSigning(trySignAlgorithm, this.provider);
                }
                catch (Exception e) {
                    log.info((Object)String.format("Signature algorithm '%s' not working for provider '%s'. Exception: %s", trySignAlgorithm, this.provider, e.getMessage()));
                    continue;
                }
                log.info((Object)String.format("Signature algorithm '%s' working for provider '%s'.", trySignAlgorithm, this.provider));
                this.signAlgorithm = trySignAlgorithm;
                boolean bl = true;
                return bl;
            }
            log.info((Object)String.format("No valid signing algorithm found for the provider '%s'.", this.provider));
            boolean bl = false;
            return bl;
        }
        finally {
            this.lock.unlock();
        }
    }
}

