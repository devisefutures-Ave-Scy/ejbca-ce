package org.cesecore.keys.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.pkcs11.jacknji11.C;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKC;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CKU;
import org.pkcs11.jacknji11.CK_SESSION_INFO;
import org.pkcs11.jacknji11.Hex;
import org.pkcs11.jacknji11.LongRef;

public class Ed25519 {
    private static final Logger log = Logger.getLogger(Ed25519.class);
    
    /**
     * Generates a keypair using jacknji11 C implementation
     * 
     * @param keyAlias    key alias
     * @throws IOException
     * @throws CertificateException
     * @throws InvalidKeyException
     */
    public static void generateEd25519(final String keyAlias) throws InvalidKeyException, CertificateException, IOException{

        byte[] USER_PIN = "1234".getBytes();
        long INITSLOT = 3;
        
        LongRef sessionRef = new LongRef();
       
        C.NATIVE = new org.pkcs11.jacknji11.jna.JNA("/etc/utimaco/libcs2_pkcs11.so");
        C.Initialize();

        C.OpenSession(INITSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null, sessionRef);
        C.Login(sessionRef.value, CKU.USER, USER_PIN);

        // Generate Ed25519 key pair
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        generateKeyPairEd25519(sessionRef.value(), pubKey, privKey, keyAlias);
        
        log.info(String.format(
                        "testKeyPairEd25519: edwards25519 keypair generated. PublicKey handle: %d, PrivKey handle: %d",
                        pubKey.value(), privKey.value()));

        generateSelfCertificate(sessionRef, pubKey, privKey, keyAlias);
    }

    /**
     * Generates a public-key / private-key Ed25519 pair, create new key objects.
     * 
     * @param session    the session's handle
     * @param publicKey  gets handle of new public key
     * @param privateKey gets handle of new private key
     */
    private static void generateKeyPairEd25519(long session, LongRef publicKey, LongRef privateKey, String keyalias) {
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
                        new CKA(CKA.LABEL, ("pub-" + keyalias).getBytes()),
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
                        new CKA(CKA.LABEL, ("priv-" + keyalias).getBytes()),
                        new CKA(CKA.ID, keyalias.getBytes()),
        };
        C.GenerateKeyPair(session, new CKM(CKM.ECDSA_KEY_PAIR_GEN), pubTempl, privTempl, publicKey, privateKey);
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

    private static void generateSelfCertificate(LongRef sessionRef, LongRef pubKey, LongRef privKey, String keyAlias) throws InvalidKeyException, IOException, CertificateException{

        final long currentTime = new Date().getTime();
        final Date firstDate = new Date(currentTime - 24 * 60 * 60 * 1000);
        final Date lastDate = new Date(currentTime + (long) (30 * 24 * 60 * 60 * 365) * 1000);
        final X500Name issuer = new X500Name("CN=Dummy certificate created by a CESeCore application");
        final BigInteger serno = BigInteger.valueOf(firstDate.getTime());

        /* 
        final PublicKey publicKey = getPublicKey(sessionRef,pubKey);

        if (publicKey == null) {
            throw new InvalidKeyException("Public key is null");
        }
        */

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
        // allocate memory and call again
        for (int i = 0; i < templ.length; i++){
            templ[i].pValue = new byte[(int) templ[i].ulValueLen];
        }
        //templ[0].pValue = new byte[(int) templ[0].ulValueLen];
        rv = C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
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
        
        log.info("Generated Certificate");
    }

        
    

    private static PublicKey getPublicKey(LongRef sessionRef, LongRef pubKey) {
        CKA[] templ = new CKA[]{
            new CKA(CKA.VALUE),
            new CKA(CKA.EC_POINT),
            new CKA(CKA.EC_PARAMS)
         };
         
         long rv = C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);

        // allocate memory and call again
        for (int i = 0; i < templ.length; i++){
            templ[i].pValue = new byte[(int) templ[i].ulValueLen];
        }

        //templ[0].pValue = new byte[(int) templ[0].ulValueLen];
        rv = C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);

        log.info(templ);
        System.out.println("Key Length: " + templ[0].ulValueLen + "\n Key " + Hex.b2s(resize(templ[0].pValue,(int) templ[0].ulValueLen)));

        //final CKA ckaQ = templ[1];
        final CKA ecPoint = templ[1];

        final CKA ckaParams = templ[2];

        

        
        final org.bouncycastle.jce.spec.ECParameterSpec bcspec = ECNamedCurveTable.getParameterSpec("ED25519");
        
        X509EncodedKeySpec edSpec;
        PublicKey publicKey = null;

        try {

        edSpec = createEd25519spec(ecPoint.getValue());
        final KeyFactory keyfact = KeyFactory.getInstance("ED25519", BouncyCastleProvider.PROVIDER_NAME);
        publicKey = keyfact.generatePublic(edSpec);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return publicKey;
    }

    /** Takes the EC point bytes from an EdDSA key and creates a keyspec that we can use to generate the public key object */ 
    private static X509EncodedKeySpec createEd25519spec(byte[] ECpoint) throws IOException {
        final byte[] rawPoint;
        // Turns out that different HSMs store this field differently, guess because P11v3 is not fully implemented yet
        // SoftHSM2 uses OctetString, same as for ECDSA keys (I think this is what it should be in P11v3)
        // nCipher (12.60.x) used BitString
        
        ASN1Primitive asn1 = ASN1Primitive.fromByteArray(ECpoint);
        if (asn1 instanceof DERBitString) {
            rawPoint = ((DERBitString) asn1).getOctets();
        } else {
            // If something else than ASN1OctetString we'll get an exception here, which will propagate well 
            // and give us an informative error message
            rawPoint = ((ASN1OctetString) asn1).getOctets();
        }

        AlgorithmIdentifier algId = new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519);
        return new X509EncodedKeySpec(new SubjectPublicKeyInfo(algId, rawPoint).getEncoded());
    }

}
