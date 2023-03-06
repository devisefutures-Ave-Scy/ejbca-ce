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
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.ejbca.cvc.example.GenerateCert;
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
import org.pkcs11.jacknji11.Hex;
import org.pkcs11.jacknji11.LongRef;

public class Ed25519 {
    private final static Logger log = Logger.getLogger(Ed25519.class);
    //private static byte[] USER_PIN = "1234".getBytes();
    //private static long INITSLOT = 3;

    private static HashMap<String,HsmInformation> hsmInfoCache = new HashMap<String,HsmInformation>();

    /**
     * Generates a keypair using jacknji11 C implementation
     * 
     * @param keyAlias    key alias
     * @return 
     * @throws IOException
     * @throws CertificateException
     * @throws InvalidKeyException
     */
    public X509Certificate generateEd25519(final String keyAlias, String providerName) throws InvalidKeyException, CertificateException, IOException{

        HsmInformation hsmInfo = hsmInfoCache.get(providerName);
        LongRef sessionRef = hsmInfo.getSessionRef();
       
        /* 
        C.NATIVE = new org.pkcs11.jacknji11.jna.JNA("/etc/utimaco/libcs2_pkcs11.so");
        C.Initialize();

        C.OpenSession(INITSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null, sessionRef);
        C.Login(sessionRef.value, CKU.USER, USER_PIN);
        */

        // Generate Ed25519 key pair
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        generateKeyPairEd25519(sessionRef.value(), pubKey, privKey, keyAlias);
        
        log.info(String.format(
                        "testKeyPairEd25519: edwards25519 keypair generated. PublicKey handle: %d, PrivKey handle: %d",
                        pubKey.value(), privKey.value()));

        //PrivateKey  priv = hsmPrivKey.getInstance(privKey.value(), "Ed25519", p);

        //setPrivate(priv);
        
        return generateSelfCertificate(sessionRef, pubKey, privKey, keyAlias, hsmInfo);
    }


    /**
     * Generates a public-key / private-key Ed25519 pair, create new key objects.
     * 
     * @param session    the session's handle
     * @param publicKey  gets handle of new public key
     * @param privateKey gets handle of new private key
     */
    private void generateKeyPairEd25519(long session, LongRef publicKey, LongRef privateKey, String keyalias) {
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
        C.GenerateKeyPair(session, new CKM(CKM.ECDSA_KEY_PAIR_GEN), pubTempl, privTempl, publicKey, privateKey);
    }

    private static X509Certificate generateSelfCertificate(LongRef sessionRef, LongRef pubKey, LongRef privKey, String keyAlias, HsmInformation hsmInfo) throws InvalidKeyException, IOException, CertificateException{

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
         
        C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
        // allocate memory and call again
        for (int i = 0; i < templ.length; i++){
            templ[i].pValue = new byte[(int) templ[i].ulValueLen];
        }
        //templ[0].pValue = new byte[(int) templ[0].ulValueLen];
        C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
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

        log.info(String.format("testCertificateEd25519: Certificate:\n%s", Hex.b2s(tbsCert.getEncoded())));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream dOut = ASN1OutputStream.create(bOut);
        dOut.writeObject(tbsCert);

        byte[] certBlock = bOut.toByteArray();

        // since the algorythm is Ed25519 there's no need to create a digest.
        C.SignInit(sessionRef.value(), new CKM(CKM.ECDSA), privKey.value());

        LongRef length = new LongRef();
        C.Sign(sessionRef.value(), certBlock, null, length);
        byte[] result = new byte[(int) length.value()];
        C.Sign(sessionRef.value(), certBlock, result, length);
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
            new CKA(CKA.ID, keyAlias),
            new CKA(CKA.VALUE, cert.getEncoded())
        };
        C.CreateObject(sessionRef.value(), certTemplate, certRef);

        updateKeypairCache(keyAlias, hsmInfo);

        return cert;
    }
    

    public byte[] sign(String alias, byte[] data, String providerName){

        HsmInformation hsmInfo = hsmInfoCache.get(providerName);
        LongRef sessionRef = hsmInfo.getSessionRef();
        updateKeypairCache(alias, hsmInfo);

        /* 
        LongRef sessionRef = new LongRef();
       
        C.NATIVE = new org.pkcs11.jacknji11.jna.JNA("/etc/utimaco/libcs2_pkcs11.so");
        C.Initialize();

        C.OpenSession(INITSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null, sessionRef);
        C.Login(sessionRef.value, CKU.USER, USER_PIN);
        */

        LongRef privKey = hsmInfo.KeyPairCache.get(alias).getPrivKey();

        // since the algorythm is Ed25519 there's no need to create a digest.
        C.SignInit(sessionRef.value(), new CKM(CKM.ECDSA), privKey.value());

        LongRef length = new LongRef();
        C.Sign(sessionRef.value(), data, null, length);
        byte[] result = new byte[(int) length.value()];
        C.Sign(sessionRef.value(), data, result, length);

        log.info("Signature Done");

        return result;
    }

    public static void removeKeyPair(String alias, String providerName){

        HsmInformation hsmInfo = hsmInfoCache.get(providerName);
        LongRef sessionRef = hsmInfo.getSessionRef();


        /* 
        LongRef sessionRef = new LongRef();
       
        C.NATIVE = new org.pkcs11.jacknji11.jna.JNA("/etc/utimaco/libcs2_pkcs11.so");
        C.Initialize();

        C.OpenSession(INITSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null, sessionRef);
        C.Login(sessionRef.value, CKU.USER, USER_PIN);
        */

        if(!hsmInfo.KeyPairCache.containsKey(alias)){
            updateKeypairCache(alias,hsmInfo);
        }

        LongRef privateKey = hsmInfo.KeyPairCache.get(alias).getPrivKey();
        LongRef publicKey = hsmInfo.KeyPairCache.get(alias).getPubKey();
        LongRef certificate = hsmInfo.KeyPairCache.get(alias).getCertificate();

        long rv = C.DestroyObject(sessionRef.value(), privateKey.value());
        if (rv != CKR.OK) throw new CKRException(rv);

        long rv2 = C.DestroyObject(sessionRef.value(), publicKey.value());
        if (rv2 != CKR.OK) throw new CKRException(rv2);

        long rv3 = C.DestroyObject(sessionRef.value(), certificate.value());
        if (rv3 != CKR.OK) throw new CKRException(rv3);
        hsmInfo.KeyPairCache.remove(alias);
    }

    public static HsmInformation updateHsmInfoCache(String providerName, String tokenName, String slotLabel, String authCode, String sharedLibrary){
        if(hsmInfoCache.containsKey(providerName)){
            HsmInformation hsmInf = hsmInfoCache.get(providerName);
            if(!(hsmInf.authcode.equals(authCode))){
                C.CloseSession(hsmInf.getSessionRef().value());
                hsmInf.setAuthCode(authCode);

                LongRef sessionRef = new LongRef();
        
                C.NATIVE = new org.pkcs11.jacknji11.jna.JNA(sharedLibrary);
                C.Initialize();

                C.OpenSession(Long.parseLong(slotLabel), CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null, sessionRef);
                C.Login(sessionRef.value, CKU.USER, authCode.getBytes());

                hsmInf.setSessionRef(sessionRef);

            }
            if(!hsmInf.tokenName.contains(tokenName)){
                hsmInf.addTokenName(tokenName);
            }
            return hsmInf;
        }else{
        
            LongRef sessionRef = new LongRef();
        
            C.NATIVE = new org.pkcs11.jacknji11.jna.JNA(sharedLibrary);
            C.Initialize();

            C.OpenSession(Long.parseLong(slotLabel), CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null, sessionRef);
            C.Login(sessionRef.value, CKU.USER, authCode.getBytes());

            HsmInformation inf = new HsmInformation(authCode, slotLabel, tokenName, sessionRef, sharedLibrary);
            hsmInfoCache.put(providerName, inf);
            return inf;
        }
    }

    public static void updateCachedName(String providerName, String oldTokenName, String newTokenName) {
        HsmInformation hsmInf = hsmInfoCache.get(providerName);
        if(!hsmInf.tokenName.contains(newTokenName)){
            hsmInf.tokenName.remove(oldTokenName);
            hsmInf.tokenName.add(newTokenName);
        }
    }

    public static void removeTokenFromCache(String providerName, String tokenName){
        HsmInformation hsmInf = hsmInfoCache.get(providerName);

        if(hsmInf.tokenName.contains(tokenName)){
            hsmInf.tokenName.remove(tokenName);
        }
        if(hsmInf.tokenName.isEmpty()){
            hsmInfoCache.remove(providerName);
        }

    }

    public static void updateKeypairCache(String alias, HsmInformation hsmCache){
        if(!hsmCache.KeyPairCache.containsKey(alias)){
            LongRef privateKey = getPrivateKeyRef(alias, hsmCache.getSessionRef());
            LongRef publicKey = getPublicKeyRef(alias, hsmCache.getSessionRef());
            LongRef certificate = getCertificateRef(alias, hsmCache.getSessionRef());

            KeyPairInfo keypair = new KeyPairInfo(publicKey, privateKey, certificate);
            hsmCache.addKeyPair(alias, keypair);
            log.info("Adding " + alias + " to cache.");
        }
    }
        

    /**
     * Gets the LongRef of a Private Key through it's alias.
     * @param alias alias
     * @return LongRef of Private Key
     */
    public static LongRef getPrivateKeyRef(String alias, LongRef sessionRef){
        LongRef objectCount = new LongRef();
        long[] result = new long[1];
        CKA[] templ = new CKA[] {new CKA(CKA.LABEL, alias + "-private" )};
        C.FindObjectsInit(sessionRef.value(), templ);
        C.FindObjects(sessionRef.value(), result, objectCount);
        C.FindObjectsFinal(sessionRef.value());

        LongRef privKey = new LongRef(result[0]);
        return privKey;

    }

    /**
     * Gets the LongRef of a Public Key through it's alias.
     * @param alias alias
     * @return LongRef of Public Key
     */
    public static LongRef getCertificateRef(String alias, LongRef sessionRef){
        LongRef objectCount = new LongRef();
        long[] result = new long[1];
        CKA[] templ = new CKA[] {new CKA(CKA.LABEL, alias)};
        C.FindObjectsInit(sessionRef.value(), templ);
        C.FindObjects(sessionRef.value(), result, objectCount);
        C.FindObjectsFinal(sessionRef.value());

        LongRef certificate = new LongRef(result[0]);
        return certificate;
    }

     /**
     * Gets the Id through public key LongRef.
     * @param LongRef pubKey
     * @param LongRef sessionRef
     * @return Byte[] id
     */
    public static String getID(LongRef pubKey, LongRef sessionRef){

        CKA[] templ = new CKA[]{
            new CKA(CKA.ID),
         };
         
        C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
        // allocate memory and call again
        for (int i = 0; i < templ.length; i++){
            templ[i].pValue = new byte[(int) templ[i].ulValueLen];
        }
        //templ[0].pValue = new byte[(int) templ[0].ulValueLen];
        C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
        final CKA id = templ[0];
        return id.getValueStr();
    }

    /**
     * Gets the LongRef of a Certificate through it's alias.
     * @param alias alias
     * @return LongRef of Certificate
     */
    public static LongRef getPublicKeyRef(String alias, LongRef sessionRef){
        LongRef objectCount = new LongRef();
        long[] result = new long[1];
        CKA[] templ = new CKA[] {new CKA(CKA.LABEL, alias + "-public")};
        C.FindObjectsInit(sessionRef.value(), templ);
        C.FindObjects(sessionRef.value(), result, objectCount);
        C.FindObjectsFinal(sessionRef.value());

        LongRef pubKey = new LongRef(result[0]);
        return pubKey;
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
        private LongRef sessionRef;
        private String sharedLibrary;
        private HashMap<String,KeyPairInfo> KeyPairCache;
        

        public HsmInformation (String authcode, String slot, String tokenName, LongRef sessionRef, String sharedLibrary){
            this.authcode = authcode;
            this.slot = slot;
            this.tokenName = new ArrayList<String>();
            this.tokenName.add(tokenName);
            this.sessionRef = sessionRef;
            this.sharedLibrary = sharedLibrary;
            this.KeyPairCache = new HashMap<String,KeyPairInfo>();

        }

        public void setSessionRef(LongRef sessionRef) {
            this.sessionRef = sessionRef;
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

        public LongRef getSessionRef(){
            return this.sessionRef;
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

    public static void noCertFix(String providerName){

        List<String> aliasList = new ArrayList<String>();

        HsmInformation hsmInf = hsmInfoCache.get(providerName);
        LongRef sessionRef = hsmInf.getSessionRef();

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
            LongRef privateKey = getPrivateKeyRef(alias, sessionRef);
            LongRef publicKey = getPublicKeyRef(alias, sessionRef);
            LongRef certificate = getCertificateRef(alias, sessionRef);


            if(certificate.value == (long) 0 ){
                String id = getID(publicKey, sessionRef);
                
                try {
                    generateSelfCertificateFix(sessionRef, publicKey, privateKey, alias, hsmInf , id);
                } catch (InvalidKeyException | CertificateException | IOException e) {
                    e.printStackTrace();
                }
                
                
            }
             

        }


    }

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
         
        C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
        // allocate memory and call again
        for (int i = 0; i < templ.length; i++){
            templ[i].pValue = new byte[(int) templ[i].ulValueLen];
        }
        //templ[0].pValue = new byte[(int) templ[0].ulValueLen];
        C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
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

        log.info(String.format("testCertificateEd25519: Certificate:\n%s", Hex.b2s(tbsCert.getEncoded())));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream dOut = ASN1OutputStream.create(bOut);
        dOut.writeObject(tbsCert);

        byte[] certBlock = bOut.toByteArray();

        // since the algorythm is Ed25519 there's no need to create a digest.
        C.SignInit(sessionRef.value(), new CKM(CKM.ECDSA), privKey.value());

        LongRef length = new LongRef();
        C.Sign(sessionRef.value(), certBlock, null, length);
        byte[] result = new byte[(int) length.value()];
        C.Sign(sessionRef.value(), certBlock, result, length);
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
        C.CreateObject(sessionRef.value(), certTemplate, certRef);

        updateKeypairCache(keyAlias, hsmInfo);

        return cert;
    }

}
