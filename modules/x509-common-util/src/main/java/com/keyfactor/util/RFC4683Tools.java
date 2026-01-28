/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.commons.lang.StringUtils
 *  org.apache.log4j.Logger
 *  org.bouncycastle.asn1.ASN1Encodable
 *  org.bouncycastle.asn1.ASN1EncodableVector
 *  org.bouncycastle.asn1.ASN1ObjectIdentifier
 *  org.bouncycastle.asn1.ASN1OctetString
 *  org.bouncycastle.asn1.ASN1Primitive
 *  org.bouncycastle.asn1.ASN1Sequence
 *  org.bouncycastle.asn1.ASN1TaggedObject
 *  org.bouncycastle.asn1.DEROctetString
 *  org.bouncycastle.asn1.DERSequence
 *  org.bouncycastle.asn1.DERTaggedObject
 *  org.bouncycastle.asn1.DERUTF8String
 *  org.bouncycastle.asn1.x509.AlgorithmIdentifier
 *  org.bouncycastle.tsp.TSPAlgorithms
 *  org.bouncycastle.util.encoders.Hex
 */
package com.keyfactor.util;

import com.keyfactor.util.RandomHelper;
import com.keyfactor.util.certificate.DnComponents;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.util.encoders.Hex;

public final class RFC4683Tools {
    public static final String LIST_SEPARATOR = "::";
    public static final String SUBJECTIDENTIFICATIONMETHOD = "subjectIdentificationMethod";
    public static final String SUBJECTIDENTIFICATIONMETHOD_OBJECTID = "1.3.6.1.5.5.7.8.6";
    private static final Logger LOG = Logger.getLogger(RFC4683Tools.class);

    public static final List<ASN1ObjectIdentifier> getAllowedHashAlgorithms() {
        return new ArrayList<ASN1ObjectIdentifier>(TSPAlgorithms.ALLOWED);
    }

    public static final List<String> getAllowedHashAlgorithmOidStrings() {
        List<ASN1ObjectIdentifier> identifiers = RFC4683Tools.getAllowedHashAlgorithms();
        ArrayList<String> result = new ArrayList<String>(identifiers.size());
        for (ASN1ObjectIdentifier identifier : identifiers) {
            result.add(identifier.getId());
        }
        return result;
    }

    public static final String generateSimForInternalSanFormat(String san) throws IllegalArgumentException, NoSuchProviderException, NoSuchAlgorithmException {
        if (StringUtils.isNotBlank((String)san) && san.toUpperCase().contains("SUBJECTIDENTIFICATIONMETHOD")) {
            List<String> sims = DnComponents.getPartsFromDN(san, "SUBJECTIDENTIFICATIONMETHOD");
            for (String sim : sims) {
                if (LOG.isDebugEnabled()) {
                    LOG.info((Object)("Store user SIM strings: " + sims));
                }
                if (!StringUtils.isNotBlank((String)sim)) continue;
                String[] tokens = sim.split(LIST_SEPARATOR);
                if (tokens.length == 4) {
                    String newSim = RFC4683Tools.generateInternalSimString(tokens[0], tokens[1], tokens[2], tokens[3]);
                    san = san.replace(sim, newSim);
                    continue;
                }
                if (tokens.length == 3) continue;
                throw new IllegalArgumentException("Wrong SIM input string with " + tokens.length + " tokens.");
            }
        }
        return san;
    }

    public static final String generateInternalSimString(String hashAlogrithmOidString, String userChosenPassword, String siiType, String sii) throws IllegalArgumentException, NoSuchProviderException, NoSuchAlgorithmException {
        if (StringUtils.isBlank((String)hashAlogrithmOidString)) {
            throw new IllegalArgumentException("Hash algorithm OID string must not be null or empty: '" + hashAlogrithmOidString + "'.");
        }
        if (!RFC4683Tools.getAllowedHashAlgorithmOidStrings().contains(hashAlogrithmOidString)) {
            throw new IllegalArgumentException("Hash algorithm with OID '" + hashAlogrithmOidString + "' is not supparted for RFC4683 (SIM).");
        }
        if (StringUtils.isBlank((String)userChosenPassword) || userChosenPassword.length() < 8) {
            throw new IllegalArgumentException("The password must not be null, empty or only whitespace, and must be at least 8 characters.");
        }
        if (StringUtils.isBlank((String)siiType)) {
            throw new IllegalArgumentException("The sensitve identification information type must not be null or empty: '" + siiType + "'.");
        }
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(siiType);
        if (LOG.isTraceEnabled()) {
            LOG.trace((Object)("SIIType: " + oid.getId()));
        }
        if (StringUtils.isBlank((String)sii)) {
            throw new IllegalArgumentException("The sensitve identification information must not be null or empty: '" + sii + "'.");
        }
        StringBuilder result = new StringBuilder();
        result.append(hashAlogrithmOidString);
        MessageDigest digester = MessageDigest.getInstance(new ASN1ObjectIdentifier(hashAlogrithmOidString).getId(), "BC");
        SecureRandom random = RandomHelper.getInstance("BCSP800HYBRID");
        byte[] authorityRandom = new byte[digester.getDigestLength()];
        random.nextBytes(authorityRandom);
        String authorityRandomHex = Hex.toHexString((byte[])authorityRandom).toUpperCase();
        if (LOG.isDebugEnabled()) {
            LOG.debug((Object)("Authority random created: " + authorityRandomHex));
        }
        result.append(LIST_SEPARATOR).append(authorityRandomHex);
        if (LOG.isDebugEnabled()) {
            LOG.debug((Object)("Authority random hash created: " + authorityRandomHex));
        }
        try {
            String pepsi = RFC4683Tools.createPepsi(hashAlogrithmOidString, userChosenPassword, siiType, sii, authorityRandomHex);
            if (LOG.isDebugEnabled()) {
                LOG.debug((Object)("SIM string PEPSI created: " + pepsi));
            }
            result.append(LIST_SEPARATOR).append(pepsi);
        }
        catch (IOException e) {
            throw new IllegalArgumentException("Unable to ASN.1 encode PEPSI input, some input is invalid: ", e);
        }
        return result.toString();
    }

    public static final String createPepsi(String hashAlogrithmOidString, String userChosenPassword, String siiType, String sii, String authorityRandomHex) throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest digester = MessageDigest.getInstance(new ASN1ObjectIdentifier(hashAlogrithmOidString).getId(), "BC");
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add((ASN1Encodable)new DERUTF8String(userChosenPassword));
        v.add((ASN1Encodable)new DEROctetString(Hex.decode((String)authorityRandomHex)));
        v.add((ASN1Encodable)new ASN1ObjectIdentifier(siiType));
        v.add((ASN1Encodable)new DERUTF8String(sii));
        DERSequence seq = new DERSequence(v);
        digester.update(seq.getEncoded());
        digester.update(digester.digest());
        String pepsi = Hex.toHexString((byte[])digester.digest()).toUpperCase();
        if (LOG.isDebugEnabled()) {
            LOG.debug((Object)("SIM string PEPSI created: " + pepsi));
        }
        return pepsi;
    }

    public static final ASN1Primitive createSimGeneralName(String hashAlgorithmIdentifier, String authorityRandom, String pepsi) {
        if (LOG.isDebugEnabled()) {
            LOG.debug((Object)("Creating SIM with hash algorithem identifier " + hashAlgorithmIdentifier + ", authority random " + authorityRandom + " and PEPSI " + pepsi));
        }
        ASN1EncodableVector otherName = new ASN1EncodableVector();
        otherName.add((ASN1Encodable)new ASN1ObjectIdentifier(SUBJECTIDENTIFICATIONMETHOD_OBJECTID));
        ASN1EncodableVector simVector = new ASN1EncodableVector();
        simVector.add((ASN1Encodable)new AlgorithmIdentifier(new ASN1ObjectIdentifier(hashAlgorithmIdentifier)));
        simVector.add((ASN1Encodable)new DEROctetString(authorityRandom.getBytes()));
        simVector.add((ASN1Encodable)new DEROctetString(pepsi.getBytes()));
        otherName.add((ASN1Encodable)new DERTaggedObject(true, 0, (ASN1Encodable)new DERSequence(simVector)));
        DERTaggedObject generalName = new DERTaggedObject(false, 0, (ASN1Encodable)new DERSequence(otherName));
        if (LOG.isDebugEnabled()) {
            LOG.debug((Object)("GeneralName (type 0 - OtherName) for SIM created " + generalName.toString()));
        }
        return generalName;
    }

    public static String getSimStringSequence(ASN1Sequence sequence) {
        ASN1ObjectIdentifier id;
        if (LOG.isDebugEnabled()) {
            LOG.debug((Object)("Parsing RFC4683 (SIM) from SAN ASN.1 sequence: " + sequence));
        }
        String result = null;
        if (sequence != null && SUBJECTIDENTIFICATIONMETHOD_OBJECTID.equals((id = ASN1ObjectIdentifier.getInstance((Object)sequence.getObjectAt(0))).getId())) {
            ASN1TaggedObject oobj = ASN1TaggedObject.getInstance((Object)sequence.getObjectAt(1));
            ASN1Primitive obj = oobj.getBaseObject().toASN1Primitive();
            if (obj instanceof ASN1TaggedObject) {
                obj = ASN1TaggedObject.getInstance((Object)obj).getBaseObject().toASN1Primitive();
            }
            ASN1Sequence simVector = ASN1Sequence.getInstance((Object)obj);
            String algorithmIdentifier = null;
            if (simVector.getObjectAt(0) instanceof AlgorithmIdentifier) {
                algorithmIdentifier = AlgorithmIdentifier.getInstance((Object)simVector.getObjectAt(0)).getAlgorithm().getId();
            } else {
                ASN1Encodable encodable = ASN1Sequence.getInstance((Object)simVector.getObjectAt(0)).getObjectAt(0);
                algorithmIdentifier = encodable.toASN1Primitive().toString();
            }
            ASN1OctetString hash = ASN1OctetString.getInstance((Object)simVector.getObjectAt(1));
            ASN1OctetString pepsi = ASN1OctetString.getInstance((Object)simVector.getObjectAt(2));
            String hashString = new String(hash.getOctets());
            String pepsiString = new String(pepsi.getOctets());
            StringBuilder builder = new StringBuilder();
            result = builder.append(algorithmIdentifier).append(LIST_SEPARATOR).append(hashString).append(LIST_SEPARATOR).append(pepsiString).toString();
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug((Object)("SIM parsed from other name: " + result));
        }
        return result;
    }

    private RFC4683Tools() {
    }
}

