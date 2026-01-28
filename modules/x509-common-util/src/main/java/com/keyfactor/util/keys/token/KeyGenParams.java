/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.commons.lang.StringUtils
 */
package com.keyfactor.util.keys.token;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang.StringUtils;

public class KeyGenParams
implements Serializable {
    private static final long serialVersionUID = 1L;
    private final String keySpecification;
    private final Map<Long, Object> publicAttributesMap;
    private final Map<Long, Object> privateAttributesMap;

    public static KeyGenParamsBuilder builder(String keySpecification) {
        return new KeyGenParamsBuilder(keySpecification);
    }

    public static KeyGenParamsBuilder builder(KeyGenParams keyGenParams) {
        return new KeyGenParamsBuilder(keyGenParams);
    }

    private KeyGenParams(KeyGenParamsBuilder builder) {
        this.keySpecification = builder.keySpecification;
        this.publicAttributesMap = builder.publicAttributesMap;
        this.privateAttributesMap = builder.privateAttributesMap;
    }

    public String getKeySpecification() {
        return this.keySpecification;
    }

    public static String getKeySpecificationNumeric(String keySpec) {
        String keySpecificationNumeric = StringUtils.startsWith((String)keySpec, (String)"RSA") ? keySpec.substring("RSA".length()) : (StringUtils.startsWithIgnoreCase((String)keySpec, (String)"FALCON-512") ? keySpec.substring("FALCON-512".length()) : (StringUtils.startsWithIgnoreCase((String)keySpec, (String)"FALCON-1024") ? keySpec.substring("FALCON-1024".length()) : keySpec));
        return keySpecificationNumeric;
    }

    public Map<Long, Object> getPublicAttributesMap() {
        return new HashMap<Long, Object>(this.publicAttributesMap);
    }

    public Map<Long, Object> getPrivateAttributesMap() {
        return new HashMap<Long, Object>(this.privateAttributesMap);
    }

    public static class KeyGenParamsBuilder {
        private String keySpecification;
        private Map<Long, Object> publicAttributesMap;
        private Map<Long, Object> privateAttributesMap;

        protected KeyGenParamsBuilder(String keySpecification) {
            this.keySpecification = keySpecification;
            this.publicAttributesMap = new HashMap<Long, Object>();
            this.privateAttributesMap = new HashMap<Long, Object>();
        }

        protected KeyGenParamsBuilder(KeyGenParams keyGenParams) {
            this.keySpecification = keyGenParams.getKeySpecification();
            this.publicAttributesMap = keyGenParams.getPublicAttributesMap();
            this.privateAttributesMap = keyGenParams.getPrivateAttributesMap();
        }

        public KeyGenParamsBuilder withKeyPairTemplate(KeyPairTemplate keyPairTemplate) {
            if (keyPairTemplate == KeyPairTemplate.ENCRYPT) {
                this.privateAttributesMap.put(261L, true);
                this.privateAttributesMap.put(263L, false);
                this.privateAttributesMap.put(264L, false);
                this.publicAttributesMap.put(260L, true);
                this.publicAttributesMap.put(262L, false);
                this.publicAttributesMap.put(266L, false);
            } else if (keyPairTemplate == KeyPairTemplate.SIGN) {
                this.privateAttributesMap.put(261L, false);
                this.privateAttributesMap.put(263L, false);
                this.privateAttributesMap.put(264L, true);
                this.publicAttributesMap.put(260L, false);
                this.publicAttributesMap.put(262L, false);
                this.publicAttributesMap.put(266L, true);
            } else if (keyPairTemplate == KeyPairTemplate.SIGN_ENCRYPT) {
                this.privateAttributesMap.put(261L, true);
                this.privateAttributesMap.put(263L, false);
                this.privateAttributesMap.put(264L, true);
                this.publicAttributesMap.put(260L, true);
                this.publicAttributesMap.put(262L, false);
                this.publicAttributesMap.put(266L, true);
            } else if (keyPairTemplate == KeyPairTemplate.SIGN_ENCRYPT_DERIVE) {
                this.privateAttributesMap.put(261L, true);
                this.privateAttributesMap.put(263L, false);
                this.privateAttributesMap.put(264L, true);
                this.privateAttributesMap.put(268L, true);
                this.publicAttributesMap.put(260L, true);
                this.publicAttributesMap.put(262L, false);
                this.publicAttributesMap.put(266L, true);
            }
            return this;
        }

        public KeyGenParamsBuilder withPrivateTemplateAttribute(long attribute, boolean flag) {
            this.privateAttributesMap.put(attribute, flag);
            return this;
        }

        public KeyGenParamsBuilder setKeySpecification(String keySpecification) {
            this.keySpecification = keySpecification;
            return this;
        }

        public KeyGenParams build() {
            return new KeyGenParams(this);
        }
    }

    public static enum KeyPairTemplate {
        SIGN,
        ENCRYPT,
        SIGN_ENCRYPT,
        SIGN_ENCRYPT_DERIVE;

    }
}

