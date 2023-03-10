package org.cesecore.keys.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.pkcs11.jacknji11.C;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKC;
import org.pkcs11.jacknji11.CKK;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CKRException;
import org.pkcs11.jacknji11.CKU;
import org.pkcs11.jacknji11.CK_SESSION_INFO;
import org.pkcs11.jacknji11.LongRef;

public class Ed25519 {
    private final static Logger log = Logger.getLogger(Ed25519.class);

    private static HashMap<String,HsmInformation> hsmInfoCache = new HashMap<String,HsmInformation>();

    /**
     * Generates a keypair using jacknji11 implementation
     * 
     * @param keyAlias    key alias
     * @param providerName Name of the current provider
     * @return 
     * @throws IOException
     * @throws CertificateException
     * @throws InvalidKeyException
     */
    public X509Certificate generateEd25519(final String keyAlias, String providerName) throws InvalidKeyException, CertificateException, IOException{

        HsmInformation hsmInfo = hsmInfoCache.get(providerName);
        
        // Generate Ed25519 key pair
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        generateKeyPairEd25519(hsmInfo, pubKey, privKey, keyAlias);
        
        return generateSelfCertificate(pubKey, privKey, keyAlias, hsmInfo);
    }


    /**
     * Generates a public-key / private-key Ed25519 pair, create new key objects.
     * 
     * @param session    the session's handle
     * @param publicKey  gets handle of new public key
     * @param privateKey gets handle of new private key
     * @param keyalias the alias for the new key
     */
    private void generateKeyPairEd25519(HsmInformation hsmInfo, LongRef publicKey, LongRef privateKey, String keyalias) {
        // Attributes from PKCS #11 Cryptographic Token Interface Current Mechanisms
        // Specification Version 2.40 section 2.3.3 - ECDSA public key objects
        /*
            * DER-encoding of an ANSI X9.62 Parameters, also known as
            * "EC domain parameters".
            */
        // We use a Ed25519 key, the oid 1.3.101.112 has DER encoding in Hex 06032b6570
        // In Utimaco, EC_PARAMS needs to have the value "edwards25519"

        CKA[] pubTempl = new CKA[] {
                        new CKA(CKA.EC_PARAMS, "edwards25519"),
                        new CKA(CKA.WRAP, false),
                        new CKA(CKA.ENCRYPT, false),
                        new CKA(CKA.VERIFY, true),
                        new CKA(CKA.VERIFY_RECOVER, false),
                        new CKA(CKA.TOKEN, true),
                        new CKA(CKA.LABEL, (keyalias + "-public").getBytes()),
                        new CKA(CKA.ID, keyalias.getBytes()),
        };
        CKA[] privTempl = new CKA[] {
                        new CKA(CKA.TOKEN, true),
                        new CKA(CKA.PRIVATE, true),
                        new CKA(CKA.SENSITIVE, true),
                        new CKA(CKA.SIGN, true),
                        new CKA(CKA.SIGN_RECOVER, false),
                        new CKA(CKA.DECRYPT, false),
                        new CKA(CKA.UNWRAP, false),
                        new CKA(CKA.EXTRACTABLE, false),
                        new CKA(CKA.LABEL, (keyalias + "-private").getBytes()),
                        new CKA(CKA.ID, keyalias.getBytes()),
        };

        LongRef sessionRef = hsmInfo.getSession();
        try {
            C.GenerateKeyPair(sessionRef.value(), new CKM(CKM.ECDSA_KEY_PAIR_GEN), pubTempl, privTempl, publicKey, privateKey);
        } catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            throw new EJBException("Failed to generate Key Pair: " + keyalias, rv);
        }finally{
            hsmInfo.releaseSession(sessionRef);
            log.info("Generated KeyPair with alias: " + keyalias);
        }
    }

    /**
     * Generates the EJBCA self certificate so keys can be recognized.
     * 
     * @param sessionRef LongRef to the session
     * @param pubKey Public key of the alias
     * @param privKey Private key of the alias 
     * @param keyAlias Key Alias
     * @param hsmInfo Cache info
     * @return The X509 Certificate
     * @throws IOException
     * @throws CertificateException
     * @throws InvalidKeyException
     */
    private static X509Certificate generateSelfCertificate(LongRef pubKey, LongRef privKey, String keyAlias, HsmInformation hsmInfo) throws InvalidKeyException, IOException, CertificateException{
        LongRef sessionRef = hsmInfo.getSession();

        
        final long currentTime = new Date().getTime();
        final Date firstDate = new Date(currentTime - 24 * 60 * 60 * 1000);
        final Date lastDate = new Date(currentTime + (long) (30 * 24 * 60 * 60 * 365) * 1000);
        final X500Name issuer = new X500Name("CN=Dummy certificate created by a CESeCore application");
        final BigInteger serno = BigInteger.valueOf(firstDate.getTime());


        Calendar expiry = Calendar.getInstance();
                int validity = (30 * 24 * 60 * 60 * 365) * 1000;
                expiry.add(Calendar.DAY_OF_YEAR, validity);

        // Certificate structure
        V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();
        certGen.setSerialNumber(new ASN1Integer(serno));

        CKA[] templ = new CKA[]{
            new CKA(CKA.VALUE),
            new CKA(CKA.EC_POINT),
            new CKA(CKA.EC_PARAMS)
        };
        
        try{
            C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
            // allocate memory and call again
            for (int i = 0; i < templ.length; i++){
                templ[i].pValue = new byte[(int) templ[i].ulValueLen];
            }

            C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
        }catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            throw new EJBException("Couldn't get EC params or point.", rv);
        }
        
        final CKA ecPoint = templ[0];
        
        certGen.setIssuer(issuer);
        certGen.setSubject(issuer);
        certGen.setStartDate(new Time(firstDate));
        certGen.setEndDate(new Time(lastDate));
        certGen.setSubjectPublicKeyInfo(
                                new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                                ecPoint.getValue()));

        certGen.setSignature(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519));

        // generate certificate
        TBSCertificate tbsCert = certGen.generateTBSCertificate();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream dOut = ASN1OutputStream.create(bOut);
        dOut.writeObject(tbsCert);

        byte[] certBlock = bOut.toByteArray();
        byte[] signature;

        try{
            // since the algorythm is Ed25519 there's no need to create a digest.
            C.SignInit(sessionRef.value(), new CKM(CKM.ECDSA), privKey.value());

            LongRef length = new LongRef();
            C.Sign(sessionRef.value(), certBlock, null, length);

            byte[] result = new byte[(int) length.value()];
            C.Sign(sessionRef.value(), certBlock, result, length);

            signature = resize(result, (int) length.value());

        }catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            throw new EJBException("Couldn't sign self signed certificate", rv);
        }

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbsCert);
        v.add(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519));
        v.add(new DERBitString(signature));

        DERSequence der = new DERSequence(v);
        ByteArrayInputStream baos = new ByteArrayInputStream(der.getEncoded());

        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(baos);

        LongRef certRef = new LongRef();

        CKA[] certTemplate = new CKA[] {
            new CKA(CKA.CLASS, CKO.CERTIFICATE),
            new CKA(CKA.CERTIFICATE_TYPE, CKC.CKC_X_509),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.LABEL, keyAlias),
            new CKA(CKA.SUBJECT, cert.getSubjectX500Principal().getEncoded()),
            new CKA(CKA.ISSUER,cert.getSubjectX500Principal().getEncoded()),
            new CKA(CKA.SERIAL_NUMBER, cert.getSerialNumber().toByteArray()),
            new CKA(CKA.ID, keyAlias),
            new CKA(CKA.VALUE, cert.getEncoded())
        };

        try{
            C.CreateObject(sessionRef.value(), certTemplate, certRef);

        }catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            throw new EJBException("Couldn't save self signed certificate", rv);
        }finally{
            hsmInfo.releaseSession(sessionRef);
            log.debug("Saved self signed certifiate with key: " + keyAlias);
        }
        
        updateKeypairCache(keyAlias, hsmInfo);

        return cert;

    }
    

    /**
     * Signs data with jacknji11 hsm implementation
     * 
     * @param alias Key Alias
     * @param data data to sign
     * @param providerName Name of current provider
     * @return signed data 
     * @throws IOException
     * @throws CertificateException
     * @throws InvalidKeyException
     */

    public byte[] sign(String alias, byte[] data, String providerName){

        HsmInformation hsmInfo = hsmInfoCache.get(providerName);
        LongRef sessionRef = hsmInfo.getSession();

        updateKeypairCache(alias, hsmInfo);
        LongRef privKey = hsmInfo.KeyPairCache.get(alias).getPrivKey();

        try{
            // since the algorythm is Ed25519 there's no need to create a digest.
            C.SignInit(sessionRef.value(), new CKM(CKM.ECDSA), privKey.value());

            LongRef length = new LongRef();
            C.Sign(sessionRef.value(), data, null, length);
            byte[] result = new byte[(int) length.value()];
            C.Sign(sessionRef.value(), data, result, length);

            return result;

        }catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            throw new EJBException("Couldn't sign data", rv);
        }finally{
            hsmInfo.releaseSession(sessionRef);
            log.debug("Signed data with: " + alias);
        }
    }

    /**
     * Removes a keypair from HSM and Cache
     * 
     * @param alias Key Alias
     * @param providerName Name of current provider
     * @return 
     * @throws IOException
     * @throws CertificateException
     * @throws InvalidKeyException
     */
    public static void removeKeyPair(String alias, String providerName){

        HsmInformation hsmInfo = hsmInfoCache.get(providerName);
        LongRef sessionRef = hsmInfo.getSession();

        if(!hsmInfo.KeyPairCache.containsKey(alias)){
            updateKeypairCache(alias,hsmInfo);
        }

        LongRef privateKey = hsmInfo.KeyPairCache.get(alias).getPrivKey();
        LongRef publicKey = hsmInfo.KeyPairCache.get(alias).getPubKey();
        LongRef certificate = hsmInfo.KeyPairCache.get(alias).getCertificate();

        try{

            long rv = C.DestroyObject(sessionRef.value(), privateKey.value());
            if (rv != CKR.OK) throw new CKRException(rv);

            long rv2 = C.DestroyObject(sessionRef.value(), publicKey.value());
            if (rv2 != CKR.OK) throw new CKRException(rv2);

            long rv3 = C.DestroyObject(sessionRef.value(), certificate.value());
            if (rv3 != CKR.OK) throw new CKRException(rv3);
            hsmInfo.KeyPairCache.remove(alias);

        }catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            throw new EJBException("Couldn't remove KeyPair: " + alias , rv);
        }finally{
            hsmInfo.releaseSession(sessionRef);
            log.debug("Removed KeyPair: " + alias);
        }
    }

    /**
     * Initializes and fills Token Cache
     * 
     * @param tokenName Name of the token
     * @param slotLabel slot of the token
     * @param authCode authentication code
     * @param sharedLibrary library path 
     * @param providerName Name of token provider
     * @return Cache instance
     * @throws IOException
     * @throws CertificateException
     * @throws InvalidKeyException
     */
    public static HsmInformation updateHsmInfoCache(String providerName, String tokenName, String slotLabel, String authCode, String sharedLibrary){
        if(hsmInfoCache.containsKey(providerName)){
            HsmInformation hsmInf = hsmInfoCache.get(providerName);
            if(!(hsmInf.authcode.equals(authCode))){    
                LongRef oldSession = hsmInf.getSession();

                try{
                    C.CloseSession(oldSession.value());
                }catch (CKRException rv) {
                    hsmInf.CloseSession(oldSession);
                    throw new EJBException("Couldn't close session", rv);
                }

                hsmInf.activeSessions.remove(oldSession);
                hsmInf.setAuthCode(authCode);
                LongRef sessionRef = new LongRef();
        
                try{
                    C.NATIVE = new org.pkcs11.jacknji11.jna.JNA(sharedLibrary);
                    C.Initialize();
                    C.OpenSession(Long.parseLong(slotLabel), CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null, sessionRef);
                    C.Login(sessionRef.value(), CKU.USER, authCode.getBytes());

                }catch (CKRException rv) {
                    if(rv.getCKR() == CKR.CRYPTOKI_ALREADY_INITIALIZED){
                        log.warn("Token already initialized: " + sharedLibrary);
                    }else if(rv.getCKR() == CKR.USER_ALREADY_LOGGED_IN){
                        log.warn("User already logged in: " + sharedLibrary);
                    }else{
                        hsmInf.CloseSession(sessionRef);
                        throw new EJBException("Couldn't open session", rv);
                    }
                }finally{
                    hsmInf.releaseSession(sessionRef);
                    log.debug("Changed Token Password");
                }
            }
            if(!hsmInf.tokenName.contains(tokenName)){
                hsmInf.addTokenName(tokenName);
            }

            return hsmInf;
            
        }else{
        
            LongRef sessionRef = new LongRef();
            HsmInformation inf = null;

            try{
                C.NATIVE = new org.pkcs11.jacknji11.jna.JNA(sharedLibrary);
                C.Initialize();
                C.OpenSession(Long.parseLong(slotLabel), CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null, sessionRef);
                C.Login(sessionRef.value(), CKU.USER, authCode.getBytes());
                
                inf = new HsmInformation(authCode, slotLabel, tokenName, sessionRef, sharedLibrary);
                hsmInfoCache.put(providerName, inf);
            }catch (CKRException rv) {
                if(rv.getCKR() == CKR.CRYPTOKI_ALREADY_INITIALIZED){
                    log.warn("Token already initialized: " + sharedLibrary);
                }else if(rv.getCKR() == CKR.USER_ALREADY_LOGGED_IN){
                    log.warn("User already logged in: " + sharedLibrary);
                }else{
                    if(inf != null){
                        inf.CloseSession(sessionRef);
                    }
                    throw new EJBException("Couldn't open session", rv);
                }
            }finally{
                if(inf != null){
                    inf.releaseSession(sessionRef);
                }
                log.debug("Opened Session");
            }

            if(inf == null){
                throw new EJBException("Couldn't open session");
            }

            return inf;

        }
    }

    /**
     * Changes name of token in Cache
     * 
     * @param providerName Name of current provider
     * @param oldTokenName Old Name to be changed
     * @param newTokenName New Name 
     * @return 
     * @throws IOException
     * @throws CertificateException
     * @throws InvalidKeyException
     */
    public static void updateCachedName(String providerName, String oldTokenName, String newTokenName) {
        HsmInformation hsmInf = hsmInfoCache.get(providerName);
        if(!hsmInf.tokenName.contains(newTokenName)){
            hsmInf.tokenName.remove(oldTokenName);
            hsmInf.tokenName.add(newTokenName);
        }
    }

    /**
     * Removes a token from Cache
     * 
     * @param tokenName Name of the token
     * @param providerName Name of provider
     * @return 
     * @throws IOException
     * @throws CertificateException
     * @throws InvalidKeyException
     */
    public static void removeTokenFromCache(String providerName, String tokenName){
        HsmInformation hsmInf = hsmInfoCache.get(providerName);

        if(hsmInf != null && hsmInf.tokenName != null && hsmInf.tokenName.contains(tokenName)){
            hsmInf.tokenName.remove(tokenName);
        }
        if(hsmInf != null && hsmInf.tokenName != null && hsmInf.tokenName.isEmpty()){
            hsmInfoCache.remove(providerName);
        }

    }

    /**
     * Updates the Cache with keypairs
     * 
     * @param alias Key Alias
     * @param hsmCache Cache
     * @return 
     * @throws IOException
     * @throws CertificateException
     * @throws InvalidKeyException
     */
    public static void updateKeypairCache(String alias, HsmInformation hsmCache){
        if(!hsmCache.KeyPairCache.containsKey(alias)){
            LongRef privateKey = getPrivateKeyRef(alias, hsmCache);
            LongRef publicKey = getPublicKeyRef(alias, hsmCache);
            LongRef certificate = getCertificateRef(alias, hsmCache);

            KeyPairInfo keypair = new KeyPairInfo(publicKey, privateKey, certificate);
            hsmCache.addKeyPair(alias, keypair);
            if (log.isDebugEnabled()) {
                log.debug("Adding " + alias + " to cache.");
            }
        }
    }
        

    /**
     * Gets the LongRef of a Private Key through it's alias.
     * @param alias alias
     * @param sessionRef Ref of the C session
     * @return LongRef of Private Key
     */
    public static LongRef getPrivateKeyRef(String alias, HsmInformation hsmCache){
        LongRef sessionRef = hsmCache.getSession();
        LongRef objectCount = new LongRef();
        long[] result = new long[1];
        CKA[] templ = new CKA[] {new CKA(CKA.LABEL, alias + "-private" )};
        long rv = C.FindObjectsInit(sessionRef.value(), templ);
        if (rv != CKR.OK) throw new CKRException(rv);
        long rv2 = C.FindObjects(sessionRef.value(), result, objectCount);
        if (rv2 != CKR.OK) throw new CKRException(rv2);
        long rv3 = C.FindObjectsFinal(sessionRef.value());
        if (rv3 != CKR.OK) throw new CKRException(rv3);

        LongRef privKey = new LongRef(result[0]);

        hsmCache.releaseSession(sessionRef);

        return privKey;

    }

    /**
     * Gets the LongRef of a Certificate through it's alias.
     * @param alias alias
     * @param sessionRef Ref of the C session
     * @return LongRef of Certificate
     */
    public static LongRef getCertificateRef(String alias, HsmInformation hsmCache){
        LongRef sessionRef = hsmCache.getSession();

        LongRef objectCount = new LongRef();
        long[] result = new long[1];
        CKA[] templ = new CKA[] {new CKA(CKA.LABEL, alias)};
        long rv = C.FindObjectsInit(sessionRef.value(), templ);
        if (rv != CKR.OK) throw new CKRException(rv);
        long rv2 = C.FindObjects(sessionRef.value(), result, objectCount);
        if (rv2 != CKR.OK) throw new CKRException(rv2);
        long rv3 = C.FindObjectsFinal(sessionRef.value());
        if (rv3 != CKR.OK) throw new CKRException(rv3);

        LongRef certificate = new LongRef(result[0]);

        hsmCache.releaseSession(sessionRef);

        return certificate;
    }

     /**
     * Gets the Id through public key LongRef.
     * @param LongRef pubKey
     * @param sessionRef Ref of the C session
     * @return String id
     */
    public static String getID(LongRef pubKey, HsmInformation hsmCache){
        LongRef sessionRef = hsmCache.getSession();

        CKA[] templ = new CKA[]{
            new CKA(CKA.ID),
         };
         
        long rv = C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
        if (rv != CKR.OK) throw new CKRException(rv);
        // allocate memory and call again
        for (int i = 0; i < templ.length; i++){
            templ[i].pValue = new byte[(int) templ[i].ulValueLen];
        }
        //templ[0].pValue = new byte[(int) templ[0].ulValueLen];
        long rv2 = C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
        if (rv2 != CKR.OK) throw new CKRException(rv2);
        final CKA id = templ[0];

        hsmCache.releaseSession(sessionRef);
        return id.getValueStr();
    }

    /**
     * Gets the LongRef of a Public Key through it's alias.
     * @param alias alias
     * @param sessionRef Ref of the C session
     * @return LongRef of Public Key
     */
    public static LongRef getPublicKeyRef(String alias, HsmInformation hsmCache){

        LongRef sessionRef = hsmCache.getSession();
        LongRef objectCount = new LongRef();
        long[] result = new long[1];
        CKA[] templ = new CKA[] {new CKA(CKA.LABEL, alias + "-public")};
        long rv = C.FindObjectsInit(sessionRef.value(), templ);
        if (rv != CKR.OK) throw new CKRException(rv);
        long rv2 = C.FindObjects(sessionRef.value(), result, objectCount);
        if (rv2 != CKR.OK) throw new CKRException(rv2);
        long rv3 = C.FindObjectsFinal(sessionRef.value());
        if (rv3 != CKR.OK) throw new CKRException(rv3);

        LongRef pubKey = new LongRef(result[0]);
        hsmCache.releaseSession(sessionRef);
        return pubKey;
    }

     /**
     * Gets the key algorithm through public key LongRef.
     * @param LongRef pubKey
     * @param sessionRef Ref of the C session
     * @return String id
     */
    public static String getAlgo(LongRef pubKey, HsmInformation hsmCache){
        LongRef sessionRef = hsmCache.getSession();

        CKA[] templ = new CKA[]{
            new CKA(CKA.KEY_TYPE),
         };
         
        long rv = C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
        if (rv != CKR.OK) throw new CKRException(rv);
        // allocate memory and call again
        for (int i = 0; i < templ.length; i++){
            templ[i].pValue = new byte[(int) templ[i].ulValueLen];
        }
        //templ[0].pValue = new byte[(int) templ[0].ulValueLen];
        long rv2 = C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
        if (rv2 != CKR.OK) throw new CKRException(rv2);

        final CKA algo = templ[0];

        hsmCache.releaseSession(sessionRef);
        
        return CKK.L2S(algo.getValueLong());
    }

    /**
     * Gets the key algorithm through public key LongRef.
     * @param LongRef pubKey
     * @param sessionRef Ref of the C session
     * @return String id
     */
    public static String getECDSAparams(LongRef pubKey, HsmInformation hsmCache){
        LongRef sessionRef = hsmCache.getSession();

        CKA[] templ = new CKA[]{
            new CKA(CKA.EC_PARAMS),
         };
         
        long rv = C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
        if (rv != CKR.OK) throw new CKRException(rv);
        // allocate memory and call again
        for (int i = 0; i < templ.length; i++){
            templ[i].pValue = new byte[(int) templ[i].ulValueLen];
        }
        //templ[0].pValue = new byte[(int) templ[0].ulValueLen];
        long rv2 = C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
        if (rv2 != CKR.OK) throw new CKRException(rv2);

        final CKA params = templ[0];
        
        hsmCache.releaseSession(sessionRef);
        return params.getValueStr();
    }

    /**
     * Gets the key algorithm through public key LongRef.
     * @param LongRef pubKey
     * @param sessionRef Ref of the C session
     * @return String id
     */
    public static BigInteger getRsaModulus(LongRef pubKey, HsmInformation hsmCache){
        LongRef sessionRef = hsmCache.getSession();

        CKA[] templ = new CKA[]{
            new CKA(CKA.MODULUS),
         };

        long rv = C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
        if (rv != CKR.OK) throw new CKRException(rv);
        // allocate memory and call again
        for (int i = 0; i < templ.length; i++){
            templ[i].pValue = new byte[(int) templ[i].ulValueLen];
        }
        //templ[0].pValue = new byte[(int) templ[0].ulValueLen];
        long rv2 = C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
        if (rv2 != CKR.OK) throw new CKRException(rv2);

        final CKA mod = templ[0];

        hsmCache.releaseSession(sessionRef);
        
        return mod.getValueBigInt();
    }

    /**
     * Gets the key algorithm through public key LongRef.
     * @param LongRef pubKey
     * @param sessionRef Ref of the C session
     * @return String id
     */
    public static BigInteger getRsaPublicExponent(LongRef pubKey, HsmInformation hsmCache){

        LongRef sessionRef = hsmCache.getSession();

        CKA[] templ = new CKA[]{
            new CKA(CKA.PUBLIC_EXPONENT),
         };

        long rv = C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
        if (rv != CKR.OK) throw new CKRException(rv);
        // allocate memory and call again
        for (int i = 0; i < templ.length; i++){
            templ[i].pValue = new byte[(int) templ[i].ulValueLen];
        }
        //templ[0].pValue = new byte[(int) templ[0].ulValueLen];
        long rv2 = C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
        if (rv2 != CKR.OK) throw new CKRException(rv2);

        final CKA exp = templ[0];
        
        return exp.getValueBigInt();
    }

    /**
     * Gets the key algorithm through public key LongRef.
     * @param LongRef pubKey
     * @param sessionRef Ref of the C session
     * @return String id
     */
    public static Long getRsaModulusBits(LongRef pubKey, HsmInformation hsmCache){

        LongRef sessionRef = hsmCache.getSession();

        CKA[] templ = new CKA[]{
            new CKA(CKA.MODULUS_BITS),
         };
         
        long rv = C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
        if (rv != CKR.OK) throw new CKRException(rv);
        // allocate memory and call again
        for (int i = 0; i < templ.length; i++){
            templ[i].pValue = new byte[(int) templ[i].ulValueLen];
        }
        //templ[0].pValue = new byte[(int) templ[0].ulValueLen];
        long rv2 = C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
        if (rv2 != CKR.OK) throw new CKRException(rv2);

        final CKA bits = templ[0];

        hsmCache.releaseSession(sessionRef);
        
        return bits.getValueLong();
    }

    

    /**
     * Resize buf to specified length. If buf already size 'newSize', then return buf, else return resized buf.
     * @param buf buf
     * @param newSize length to resize to
     * @return if buf already size 'newSize', then return buf, else return resized buf
     */
    private static byte[] resize(byte[] buf, int newSize) {
        if (buf == null || newSize >= buf.length) {
            return buf;
        }
        byte[] result = new byte[newSize];
        System.arraycopy(buf, 0, result, 0, result.length);
        return result;
    }

    static public class HsmInformation{
        private String authcode;
        private String slot;
        private List<String> tokenName;
        //private LongRef sessionRef;
        private final LinkedList<LongRef> idleSessions = new LinkedList<>();
        private final LinkedList<LongRef> activeSessions = new LinkedList<>();
        private String sharedLibrary;
        private HashMap<String,KeyPairInfo> KeyPairCache;
        

        public HsmInformation (String authcode, String slot, String tokenName, LongRef sessionRef, String sharedLibrary){
            this.authcode = authcode;
            this.slot = slot;
            this.tokenName = new ArrayList<String>();
            this.tokenName.add(tokenName);
            //this.sessionRef = sessionRef;
            this.idleSessions.push(sessionRef);
            this.sharedLibrary = sharedLibrary;
            this.KeyPairCache = new HashMap<String,KeyPairInfo>();

        }

        //public void setSessionRef(LongRef sessionRef) {
        //    this.sessionRef = sessionRef;
        //}

        public synchronized void releaseSession(LongRef sessionRef){
            if(activeSessions.contains(sessionRef)){
                activeSessions.remove(sessionRef);

            }else{
                log.warn("Session not active: " + sessionRef);
            }
        }

        public synchronized LongRef getSession(){
            LongRef sessionRef = new LongRef();
            if(idleSessions.size() == 0){
                try{
                    C.OpenSession(Long.parseLong(this.slot), CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null, sessionRef);
                    if(log.isDebugEnabled()){
                        log.debug("iddleSessions is empty, adding new session: " + sessionRef.value());
                    }
                }catch (CKRException rv){
                    throw new EJBException(rv);
                }
            }else{
                sessionRef = idleSessions.pop();
                if(log.isDebugEnabled()){
                    log.debug("Removing session from iddle: " + sessionRef.value());
                }
            }
            activeSessions.push(sessionRef);
            return sessionRef;
        }

        // Closing the last session causes the user to be logged out. A new iddle session will be created in this case to prevent logout.
        public synchronized void CloseSession(LongRef sessionRef){
            if(idleSessions.size() == 0 && activeSessions.size() == 1){
                releaseSession(getSession());
            }

            try {
                C.CloseSession(sessionRef.value());
            } catch (CKRException rv) {
                throw new EJBException(rv);
            }

            if(activeSessions.contains(sessionRef)){
                activeSessions.remove(sessionRef);
            }else if(idleSessions.contains(sessionRef)){
                idleSessions.remove(sessionRef);
            }

            if(log.isDebugEnabled()){
                log.debug("Closed Session: " + sessionRef.value());
            }

        }

        public void setAuthCode(String authcode) {
            this.authcode = authcode;
        }

        public String getAuthCode(){
            return this.authcode;
        }

        public List<String> getTokenNames(){
            return this.tokenName;
        }

        public void addTokenName(String tokenName){
            this.tokenName.add(tokenName);
        }

        public String getSlot(){
            return this.slot;
        }


        public String getSharedLibrary(){
            return this.sharedLibrary;
        }

        public void addKeyPair(String alias, KeyPairInfo keypair){
            KeyPairCache.put(alias, keypair);
        }

        public KeyPairInfo getKeyPair(String alias){
            return KeyPairCache.get(alias);
        }
    }

    static public class KeyPairInfo{
        private LongRef pubKey;
        private LongRef privKey;
        private LongRef certificate;

        public KeyPairInfo(LongRef pubkey, LongRef privKey, LongRef certificate){
            this.pubKey = pubkey;
            this.privKey = privKey;
            this.certificate = certificate;
        }

        public LongRef getPubKey(){
            return this.pubKey;
        }

        public LongRef getPrivKey(){
            return this.privKey;
        }

        public LongRef getCertificate(){
            return this.certificate;
        }

        public void setPubKey(LongRef pubKey){
            this.pubKey = pubKey;
        }

        public void setPrivKey(LongRef privKey){
            this.pubKey = privKey;
        }

        public void setCertificate(LongRef certificate){
            this.pubKey = certificate;
        }

    }

    /**
     * Fixes keys without certificate so they can be seen by EJBCA. The keys need to follow the format alias-private and alias-public for it to work.
     * @param providerName Name of the provider
     * @return
     */
    public static void noCertFix(String providerName){

        List<String> aliasList = new ArrayList<String>();

        HsmInformation hsmInf = hsmInfoCache.get(providerName);
        LongRef sessionRef = hsmInf.getSession();

        LongRef objectCount = new LongRef();
        long[] found = new long[1024];

        CKA[] templ = new CKA[] {new CKA(CKA.CLASS, CKO.PUBLIC_KEY)};

        long rv = C.FindObjectsInit(sessionRef.value(), templ);
        if (rv != CKR.OK) throw new CKRException(rv);
        long rv2 = C.FindObjects(sessionRef.value(), found, objectCount);
        if (rv2 != CKR.OK) throw new CKRException(rv2);

        long count = objectCount.value();

        long[] result = new long[(int) count];
        System.arraycopy(found, 0, result, 0, result.length);
        
        long rv3 = C.FindObjectsFinal(sessionRef.value());
        if (rv3 != CKR.OK) throw new CKRException(rv3);


        for(long ref : result){
            LongRef tempRef = new LongRef(ref);

            CKA[] templ2 = new CKA[]{
                new CKA(CKA.LABEL),
             };

            long rv4 = C.GetAttributeValue(sessionRef.value(), tempRef.value(), templ2);
            if (rv4 != CKR.OK) throw new CKRException(rv4);

            // allocate memory and call again
            for (int i = 0; i < templ.length; i++){
                templ2[i].pValue = new byte[(int) templ2[i].ulValueLen];
            }
            //templ[0].pValue = new byte[(int) templ[0].ulValueLen];
            long rv5 = C.GetAttributeValue(sessionRef.value(), tempRef.value(), templ2);
            if (rv5 != CKR.OK) throw new CKRException(rv5);
            final CKA label = templ2[0];

            String s = label.getValueStr();
            String alias = s.substring(0, s.length() - 7);

            aliasList.add(alias);
        }

        for(String alias : aliasList){
            LongRef privateKey = getPrivateKeyRef(alias, hsmInf);
            LongRef publicKey = getPublicKeyRef(alias, hsmInf);
            String algo = getAlgo(publicKey, hsmInf);
            LongRef certificate = getCertificateRef(alias, hsmInf);

            if(algo.equals("EC")){
                
                String ecParams = getECDSAparams(publicKey, hsmInf);
                 
                if(ecParams.equals("edwards25519") && certificate.value == (long) 0 ){
                    String id = getID(publicKey, hsmInf);
                    
                    try {
                        generateSelfCertificateFix(sessionRef, publicKey, privateKey, alias, hsmInf , id);
                    } catch (InvalidKeyException | CertificateException | IOException e) {
                        e.printStackTrace();
                    }
                }

            }else if(algo.equals("RSA") && certificate.value == (long) 0 ){

                String id = getID(publicKey, hsmInf);
                    
                try {
                    generateSelfCertificateFixRsa(sessionRef, publicKey, privateKey, alias, hsmInf , id);
                } catch (InvalidKeyException | CertificateException | IOException e) {
                    e.printStackTrace();
                }

            }

            
        
        }

        hsmInf.releaseSession(sessionRef);

    }

    /**
     * Copy of generateSelfCertificate above but used only for fixing certificates so it can have same IDs
     * @param sessionRef LongRef to the session
     * @param pubKey Public key of the alias
     * @param privKey Private key of the alias 
     * @param keyAlias Key Alias
     * @param hsmInfo Cache info
     * @return The X509 Certificate
     * @throws IOException
     * @throws CertificateException
     * @throws InvalidKeyException
     */
    private static X509Certificate generateSelfCertificateFix(LongRef sessionRef, LongRef pubKey, LongRef privKey, String keyAlias, HsmInformation hsmInfo, String id) throws InvalidKeyException, IOException, CertificateException{

        final long currentTime = new Date().getTime();
        final Date firstDate = new Date(currentTime - 24 * 60 * 60 * 1000);
        final Date lastDate = new Date(currentTime + (long) (30 * 24 * 60 * 60 * 365) * 1000);
        final X500Name issuer = new X500Name("CN=Dummy certificate created by a CESeCore application");
        final BigInteger serno = BigInteger.valueOf(firstDate.getTime());


        Calendar expiry = Calendar.getInstance();
                int validity = (30 * 24 * 60 * 60 * 365) * 1000;
                expiry.add(Calendar.DAY_OF_YEAR, validity);

        // Certificate structure
        V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();
        certGen.setSerialNumber(new ASN1Integer(serno));

        CKA[] templ = new CKA[]{
            new CKA(CKA.VALUE),
            new CKA(CKA.EC_POINT),
            new CKA(CKA.EC_PARAMS)
         };
         
        long rv = C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
        if (rv != CKR.OK) throw new CKRException(rv);
        // allocate memory and call again
        for (int i = 0; i < templ.length; i++){
            templ[i].pValue = new byte[(int) templ[i].ulValueLen];
        }
        //templ[0].pValue = new byte[(int) templ[0].ulValueLen];
        long rv2 = C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
        if (rv2 != CKR.OK) throw new CKRException(rv2);
        final CKA ecPoint = templ[0];
        
        certGen.setIssuer(issuer);
        certGen.setSubject(issuer);
        certGen.setStartDate(new Time(firstDate));
        certGen.setEndDate(new Time(lastDate));
        certGen.setSubjectPublicKeyInfo(
                                new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                                ecPoint.getValue()));

        certGen.setSignature(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519));

        // generate certificate
        TBSCertificate tbsCert = certGen.generateTBSCertificate();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream dOut = ASN1OutputStream.create(bOut);
        dOut.writeObject(tbsCert);

        byte[] certBlock = bOut.toByteArray();

        // since the algorythm is Ed25519 there's no need to create a digest.
        long rv3 = C.SignInit(sessionRef.value(), new CKM(CKM.ECDSA), privKey.value());
        if (rv3 != CKR.OK) throw new CKRException(rv3);

        LongRef length = new LongRef();
        long rv4 = C.Sign(sessionRef.value(), certBlock, null, length);
        if (rv4 != CKR.OK) throw new CKRException(rv4);
        byte[] result = new byte[(int) length.value()];
        long rv5 = C.Sign(sessionRef.value(), certBlock, result, length);
        if (rv5 != CKR.OK) throw new CKRException(rv5);
        byte[] signature = resize(result, (int) length.value());

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbsCert);
        v.add(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519));
        v.add(new DERBitString(signature));

        DERSequence der = new DERSequence(v);
        ByteArrayInputStream baos = new ByteArrayInputStream(der.getEncoded());

        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(baos);

        LongRef certRef = new LongRef();

        CKA[] certTemplate = new CKA[] {
            new CKA(CKA.CLASS, CKO.CERTIFICATE),
            new CKA(CKA.CERTIFICATE_TYPE, CKC.CKC_X_509),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.LABEL, keyAlias),
            new CKA(CKA.SUBJECT, cert.getSubjectX500Principal().getEncoded()),
            new CKA(CKA.ISSUER,cert.getSubjectX500Principal().getEncoded()),
            new CKA(CKA.SERIAL_NUMBER, cert.getSerialNumber().toByteArray()),
            new CKA(CKA.ID, id),
            new CKA(CKA.VALUE, cert.getEncoded())
        };
        long rv6 = C.CreateObject(sessionRef.value(), certTemplate, certRef);
        if (rv6 != CKR.OK) throw new CKRException(rv6);

        updateKeypairCache(keyAlias, hsmInfo);

        return cert;
    }

    /**
     * Copy of generateSelfCertificate above but used only for fixing certificates so it can have same IDs
     * @param sessionRef LongRef to the session
     * @param pubKey Public key of the alias
     * @param privKey Private key of the alias 
     * @param keyAlias Key Alias
     * @param hsmInfo Cache info
     * @return The X509 Certificate
     * @throws IOException
     * @throws CertificateException
     * @throws InvalidKeyException
     */
    private static X509Certificate generateSelfCertificateFixRsa(LongRef sessionRef, LongRef pubKey, LongRef privKey, String keyAlias, HsmInformation hsmInfo, String id) throws InvalidKeyException, IOException, CertificateException{

        final long currentTime = new Date().getTime();
        final Date firstDate = new Date(currentTime - 24 * 60 * 60 * 1000);
        final Date lastDate = new Date(currentTime + (long) (30 * 24 * 60 * 60 * 365) * 1000);
        final X500Name issuer = new X500Name("CN=Dummy certificate created by a CESeCore application");
        final BigInteger serno = BigInteger.valueOf(firstDate.getTime());


        Calendar expiry = Calendar.getInstance();
                int validity = (30 * 24 * 60 * 60 * 365) * 1000;
                expiry.add(Calendar.DAY_OF_YEAR, validity);

        // Certificate structure
        V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();
        certGen.setSerialNumber(new ASN1Integer(serno));

        byte[] modulus = getRsaModulus(pubKey, hsmInfo).toByteArray();
        byte[] publicExponent =  getRsaPublicExponent(pubKey, hsmInfo).toByteArray();

        final BigInteger n = new BigInteger(1, modulus);
        final BigInteger e = new BigInteger(1, publicExponent);

        RSAPublicKey pk = new RSAPublicKey(n, e);

        
        certGen.setIssuer(issuer);
        certGen.setSubject(issuer);
        certGen.setStartDate(new Time(firstDate));
        certGen.setEndDate(new Time(lastDate));
        certGen.setSubjectPublicKeyInfo(new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), pk));

        certGen.setSignature(new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption, DERNull.INSTANCE));

        // generate certificate
        TBSCertificate tbsCert = certGen.generateTBSCertificate();

        //Sign certificate
        SHA1Digest digester = new SHA1Digest();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream dOut = ASN1OutputStream.create(bOut);
        dOut.writeObject(tbsCert);
        byte[] certBlock = bOut.toByteArray();

        // first create digest
        digester.update(certBlock, 0, certBlock.length);
        byte[] hash = new byte[digester.getDigestSize()];
        digester.doFinal(hash, 0);

        DigestInfo dInfo = new DigestInfo( new AlgorithmIdentifier(X509ObjectIdentifiers.id_SHA1, null), hash);
        byte[] digest = dInfo.getEncoded();

        long rv3 = C.SignInit(sessionRef.value(), new CKM(CKM.SHA1_RSA_PKCS), privKey.value());
        if (rv3 != CKR.OK) throw new CKRException(rv3);

        LongRef length = new LongRef();
        long rv4 = C.Sign(sessionRef.value(), digest, null, length);
        if (rv4 != CKR.OK) throw new CKRException(rv4);
        byte[] result = new byte[(int) length.value()];
        long rv5 = C.Sign(sessionRef.value(), digest, result, length);
        if (rv5 != CKR.OK) throw new CKRException(rv5);
        byte[] signature = resize(result, (int) length.value());

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbsCert);
        v.add(new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption, DERNull.INSTANCE));
        v.add(new DERBitString(signature));

        DERSequence der = new DERSequence(v);
        ByteArrayInputStream baos = new ByteArrayInputStream(der.getEncoded());

        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(baos);

        LongRef certRef = new LongRef();

        CKA[] certTemplate = new CKA[] {
            new CKA(CKA.CLASS, CKO.CERTIFICATE),
            new CKA(CKA.CERTIFICATE_TYPE, CKC.CKC_X_509),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.LABEL, keyAlias),
            new CKA(CKA.SUBJECT, cert.getSubjectX500Principal().getEncoded()),
            new CKA(CKA.ISSUER,cert.getSubjectX500Principal().getEncoded()),
            new CKA(CKA.SERIAL_NUMBER, cert.getSerialNumber().toByteArray()),
            new CKA(CKA.ID, id),
            new CKA(CKA.VALUE, cert.getEncoded())
        };
        long rv6 = C.CreateObject(sessionRef.value(), certTemplate, certRef);
        if (rv6 != CKR.OK) throw new CKRException(rv6);

        updateKeypairCache(keyAlias, hsmInfo);

        return cert;
    }

}
