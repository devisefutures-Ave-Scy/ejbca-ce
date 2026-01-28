/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.commons.lang.ArrayUtils
 *  org.apache.commons.lang.StringUtils
 *  org.apache.log4j.Logger
 *  org.bouncycastle.asn1.ASN1Encodable
 *  org.bouncycastle.asn1.ASN1EncodableVector
 *  org.bouncycastle.asn1.ASN1GeneralString
 *  org.bouncycastle.asn1.ASN1IA5String
 *  org.bouncycastle.asn1.ASN1Integer
 *  org.bouncycastle.asn1.ASN1ObjectIdentifier
 *  org.bouncycastle.asn1.ASN1OctetString
 *  org.bouncycastle.asn1.ASN1Primitive
 *  org.bouncycastle.asn1.ASN1Sequence
 *  org.bouncycastle.asn1.ASN1TaggedObject
 *  org.bouncycastle.asn1.ASN1UTF8String
 *  org.bouncycastle.asn1.DERGeneralString
 *  org.bouncycastle.asn1.DERIA5String
 *  org.bouncycastle.asn1.DEROctetString
 *  org.bouncycastle.asn1.DERSequence
 *  org.bouncycastle.asn1.DERTaggedObject
 *  org.bouncycastle.asn1.DERUTF8String
 *  org.bouncycastle.asn1.x500.AttributeTypeAndValue
 *  org.bouncycastle.asn1.x500.RDN
 *  org.bouncycastle.asn1.x500.X500Name
 *  org.bouncycastle.asn1.x500.X500NameBuilder
 *  org.bouncycastle.asn1.x500.X500NameStyle
 *  org.bouncycastle.asn1.x500.style.IETFUtils
 *  org.bouncycastle.asn1.x509.Extension
 *  org.bouncycastle.asn1.x509.GeneralName
 *  org.bouncycastle.asn1.x509.GeneralNames
 *  org.bouncycastle.util.encoders.Hex
 */
package com.keyfactor.util.certificate;

import com.keyfactor.util.CeSecoreNameStyle;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.RFC4683Tools;
import com.keyfactor.util.StringTools;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralString;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.util.encoders.Hex;

public class DnComponents {
    private static Logger log = Logger.getLogger(DnComponents.class);
    private static DnComponents obj = new DnComponents();
    private static final Pattern UNESCAPE_FIELD_REGEX = Pattern.compile("\\\\([,+\"\\\\<>; ])");
    private static HashMap<String, ASN1ObjectIdentifier> oids = new HashMap();
    private static String[] dNObjectsForward;
    private static String[] dNObjectsReverse;
    public static final String DNEMAILADDRESS = "EMAILADDRESS";
    public static final String DNQUALIFIER = "DNQUALIFIER";
    public static final String UNIQUEIDENTIFIER = "UNIQUEIDENTIFIER";
    public static final String UID = "UID";
    public static final String COMMONNAME = "COMMONNAME";
    public static final String DNSERIALNUMBER = "SERIALNUMBER";
    public static final String GIVENNAME = "GIVENNAME";
    public static final String INITIALS = "INITIALS";
    public static final String SURNAME = "SURNAME";
    public static final String TITLE = "TITLE";
    public static final String ORGANIZATIONALUNIT = "ORGANIZATIONALUNIT";
    public static final String ORGANIZATION = "ORGANIZATION";
    public static final String LOCALITY = "LOCALITY";
    public static final String STATEORPROVINCE = "STATEORPROVINCE";
    public static final String DOMAINCOMPONENT = "DOMAINCOMPONENT";
    public static final String COUNTRY = "COUNTRY";
    public static final String UNSTRUCTUREDADDRESS = "UNSTRUCTUREDADDRESS";
    public static final String UNSTRUCTUREDNAME = "UNSTRUCTUREDNAME";
    public static final String POSTALCODE = "POSTALCODE";
    public static final String BUSINESSCATEGORY = "BUSINESSCATEGORY";
    public static final String POSTALADDRESS = "POSTALADDRESS";
    public static final String TELEPHONENUMBER = "TELEPHONENUMBER";
    public static final String PSEUDONYM = "PSEUDONYM";
    public static final String STREETADDRESS = "STREETADDRESS";
    public static final String NAME = "NAME";
    public static final String ROLE = "ROLE";
    public static final String DESCRIPTION = "DESCRIPTION";
    public static final String JURISDICTIONLOCALITY = "JURISDICTIONLOCALITY";
    public static final String JURISDICTIONSTATE = "JURISDICTIONSTATE";
    public static final String JURISDICTIONCOUNTRY = "JURISDICTIONCOUNTRY";
    public static final String ORGANIZATIONIDENTIFIER = "ORGANIZATIONIDENTIFIER";
    public static final String VID = "VID";
    public static final String PID = "PID";
    public static final String RCACID = "RCACID";
    public static final String ICACID = "ICACID";
    public static final String NODEID = "NODEID";
    public static final String FABRICID = "FABRICID";
    public static final String NOCCAT = "NOCCAT";
    public static final String FWSIGNINGID = "FWSIGNINGID";
    public static final String CERTIFICATIONID = "CERTIFICATIONID";
    public static final String LEGALENTITYIDENTIFIER = "LEGALENTITYIDENTIFIER";
    public static final String MARKTYPE = "MARKTYPE";
    public static final String TRADEMARKCOUNTRYORREGIONNAME = "TRADEMARKCOUNTRYORREGIONNAME";
    public static final String TRADEMARKOFFICENAME = "TRADEMARKOFFICENAME";
    public static final String TRADEMARKIDENTIFIER = "TRADEMARKIDENTIFIER";
    public static final String WORDMARK = "WORDMARK";
    public static final String STATUTELOCALITYNAME = "STATUTELOCALITYNAME";
    public static final String STATUTESTATEORPROVINCENAME = "STATUTESTATEORPROVINCENAME";
    public static final String STATUTECOUNTRYNAME = "STATUTECOUNTRYNAME";
    public static final String STATUTECITATION = "STATUTECITATION";
    public static final String STATUTEURL = "STATUTEURL";
    public static final String PRIORUSEMARKSOURCEURL = "PRIORUSEMARKSOURCEURL";
    public static final String EMAIL = "rfc822name";
    public static final String EMAIL1 = "email";
    public static final String EMAIL2 = "EmailAddress";
    public static final String EMAIL3 = "E";
    public static final String DNS = "dNSName";
    public static final String IPADDR = "iPAddress";
    public static final String PERMANENTIDENTIFIER_SEP = "/";
    public static final String HARDWAREMODULENAME_SEP = "/";
    public static final String RFC822NAME = "RFC822NAME";
    public static final String DNSNAME = "DNSNAME";
    public static final String IPADDRESS = "IPADDRESS";
    public static final String URI = "UNIFORMRESOURCEIDENTIFIER";
    public static final String URI1 = "URI";
    public static final String URI2 = "uniformResourceId";
    public static final String UNIFORMRESOURCEID = "UNIFORMRESOURCEID";
    public static final String DIRECTORYNAME = "DIRECTORYNAME";
    public static final String UPN = "UPN";
    public static final String XMPPADDR = "XMPPADDR";
    public static final String SRVNAME = "SRVNAME";
    public static final String FASCN = "FASCN";
    public static final String GUID = "GUID";
    public static final String KRB5PRINCIPAL = "KRB5PRINCIPAL";
    public static final String PERMANENTIDENTIFIER = "PERMANENTIDENTIFIER";
    public static final String HARDWAREMODULENAME = "HARDWAREMODULENAME";
    public static final String SUBJECTIDENTIFICATIONMETHOD = "SUBJECTIDENTIFICATIONMETHOD";
    public static final String OTHERNAME = "OTHERNAME";
    public static final String X400ADDRESS = "X400ADDRESS";
    public static final String EDIPARTYNAME = "EDIPARTYNAME";
    public static final String REGISTEREDID = "REGISTEREDID";
    public static final String DATEOFBIRTH = "DATEOFBIRTH";
    public static final String PLACEOFBIRTH = "PLACEOFBIRTH";
    public static final String GENDER = "GENDER";
    public static final String COUNTRYOFCITIZENSHIP = "COUNTRYOFCITIZENSHIP";
    public static final String COUNTRYOFRESIDENCE = "COUNTRYOFRESIDENCE";
    public static final String UPN_OBJECTID = "1.3.6.1.4.1.311.20.2.3";
    public static final String XMPPADDR_OBJECTID = "1.3.6.1.5.5.7.8.5";
    public static final String SRVNAME_OBJECTID = "1.3.6.1.5.5.7.8.7";
    public static final String FASCN_OBJECTID = "2.16.840.1.101.3.6.6";
    public static final String PERMANENTIDENTIFIER_OBJECTID = "1.3.6.1.5.5.7.8.3";
    public static final String HARDWAREMODULENAME_OBJECTID = "1.3.6.1.5.5.7.8.4";
    public static final String GUID_OBJECTID = "1.3.6.1.4.1.311.25.1";
    public static final String KRB5PRINCIPAL_OBJECTID = "1.3.6.1.5.2.2";
    private static final String[] EMAILIDS;
    private static Map<String, Integer> dnNameToIdMap;
    private static Map<String, Integer> altNameToIdMap;
    private static Map<String, Integer> dirAttrToIdMap;
    private static Map<String, Integer> profileNameIdMap;
    private static Map<Integer, String> dnIdToProfileNameMap;
    private static Map<Integer, Integer> dnIdToProfileIdMap;
    private static Map<Integer, Integer> profileIdToDnIdMap;
    private static Map<Integer, String> dnErrorTextMap;
    private static Map<String, String> profileNameLanguageMap;
    private static Map<Integer, String> profileIdLanguageMap;
    private static Map<Integer, String> dnIdErrorMap;
    private static Map<Integer, String> dnIdToExtractorFieldMap;
    private static Map<Integer, String> altNameIdToExtractorFieldMap;
    private static Map<Integer, String> dirAttrIdToExtractorFieldMap;
    private static List<String> dnProfileFields;
    private static final Set<String> dnProfileFieldsHashSet;
    private static List<String> dnLanguageTexts;
    private static List<Integer> dnDnIds;
    private static List<String> altNameFields;
    private static final Set<String> altNameFieldsHashSet;
    private static List<String> altNameLanguageTexts;
    private static List<Integer> altNameDnIds;
    private static List<String> dirAttrFields;
    private static final Set<String> dirAttrFieldsHashSet;
    private static List<String> dirAttrLanguageTexts;
    private static List<Integer> dirAttrDnIds;
    private static List<String> dnExtractorFields;
    private static List<String> altNameExtractorFields;
    private static List<String> dirAttrExtractorFields;

    public static Integer getDnIdFromDnName(String dnName) {
        return dnNameToIdMap.get(dnName.toUpperCase(Locale.ROOT));
    }

    public static Integer getDnIdFromAltName(String altName) {
        return altNameToIdMap.get(altName.toUpperCase(Locale.ROOT));
    }

    public static Integer getDnIdFromDirAttr(String dirAttr) {
        return dirAttrToIdMap.get(dirAttr.toUpperCase(Locale.ROOT));
    }

    public static ASN1ObjectIdentifier getOid(String o) {
        return oids.get(o.toLowerCase(Locale.ROOT));
    }

    public static List<String> getDnProfileFields() {
        return dnProfileFields;
    }

    public static boolean isDnProfileField(String field) {
        return dnProfileFieldsHashSet.contains(field);
    }

    public static List<String> getDnLanguageTexts() {
        return dnLanguageTexts;
    }

    public static List<String> getAltNameFields() {
        return altNameFields;
    }

    public static boolean isAltNameField(String field) {
        return altNameFieldsHashSet.contains(field);
    }

    public static List<String> getAltNameLanguageTexts() {
        return altNameLanguageTexts;
    }

    public static List<String> getDirAttrFields() {
        return dirAttrFields;
    }

    public static boolean isDirAttrField(String field) {
        return dirAttrFieldsHashSet.contains(field);
    }

    public static List<Integer> getDirAttrDnIds() {
        return dirAttrDnIds;
    }

    public static List<Integer> getAltNameDnIds() {
        return altNameDnIds;
    }

    public static List<Integer> getDnDnIds() {
        return dnDnIds;
    }

    protected static List<String> getDnExtractorFields() {
        return dnExtractorFields;
    }

    public static String getDnExtractorFieldFromDnId(int field) {
        return dnIdToExtractorFieldMap.get(field);
    }

    public static List<String> getAltNameExtractorFields() {
        return altNameExtractorFields;
    }

    public static String getAltNameExtractorFieldFromDnId(int field) {
        return altNameIdToExtractorFieldMap.get(field);
    }

    protected static List<String> getDirAttrExtractorFields() {
        return dirAttrExtractorFields;
    }

    public static String getDirAttrExtractorFieldFromDnId(int field) {
        return dirAttrIdToExtractorFieldMap.get(field);
    }

    public static String dnIdToProfileName(int dnid) {
        return dnIdToProfileNameMap.get(dnid);
    }

    public static int dnIdToProfileId(int dnid) {
        return dnIdToProfileIdMap.get(dnid);
    }

    public static String getLanguageConstantFromProfileName(String name) {
        return profileNameLanguageMap.get(name);
    }

    public static String getLanguageConstantFromProfileId(int id) {
        return profileIdLanguageMap.get(id);
    }

    public static String getErrTextFromDnId(int id) {
        return dnIdErrorMap.get(id);
    }

    public static Map<String, Integer> getProfilenameIdMap() {
        return profileNameIdMap;
    }

    public static int profileIdToDnId(int profileId) {
        Integer val = profileIdToDnIdMap.get(profileId);
        if (val == null) {
            String msg = "No DN ID mapping from Profile ID " + profileId;
            log.error((Object)msg);
            throw new IllegalArgumentException(msg);
        }
        return val;
    }

    public static String[] getDnObjects(boolean ldaporder) {
        if (ldaporder) {
            return dNObjectsForward;
        }
        return DnComponents.getDnObjectsReverse();
    }

    protected static String[] getDnObjectsReverse() {
        if (dNObjectsReverse == null) {
            dNObjectsReverse = (String[])dNObjectsForward.clone();
            ArrayUtils.reverse((Object[])dNObjectsReverse);
        }
        return dNObjectsReverse;
    }

    private static void load() {
        DnComponents.loadOrdering();
        DnComponents.loadMappings();
    }

    private static void loadMappings() {
        DnComponents.loadProfileMappingsFromFile("/profilemappings.properties");
        DnComponents.loadProfileMappingsFromFile("/profilemappings_enterprise.properties");
    }

    public static boolean enterpriseMappingsExist() {
        return obj.getClass().getResourceAsStream("/profilemappings_enterprise.properties") != null;
    }

    public static boolean dnHasMultipleComponents(String dn) {
        X509NameTokenizer xt = new X509NameTokenizer(dn);
        if (xt.hasMoreTokens()) {
            xt.nextToken();
            return xt.hasMoreTokens();
        }
        return false;
    }

    public static String getCommonNameFromSubjectDn(String subjectDn) {
        List<String> commonNames;
        String commonName = null;
        if (subjectDn != null && !(commonNames = DnComponents.getPartsFromDN(subjectDn, "CN")).isEmpty() && StringUtils.isNotEmpty((String)commonNames.get(0))) {
            commonName = commonNames.get(0);
        }
        return commonName;
    }

    public static List<String> getCustomOids(String dn) {
        if (log.isTraceEnabled()) {
            log.trace((Object)(">getCustomOids: dn:'" + dn));
        }
        ArrayList<String> parts = new ArrayList<String>();
        if (dn != null) {
            X509NameTokenizer xt = new X509NameTokenizer(dn);
            while (xt.hasMoreTokens()) {
                String o = xt.nextToken().trim();
                try {
                    String oid;
                    int i = o.indexOf(61);
                    if (i <= 2 || o.charAt(1) != '.' || parts.contains(oid = o.substring(0, i))) continue;
                    new ASN1ObjectIdentifier(oid);
                    parts.add(oid);
                }
                catch (IllegalArgumentException illegalArgumentException) {}
            }
        }
        if (log.isTraceEnabled()) {
            log.trace((Object)("<getCustomOids: resulting DN part=" + ((Object)parts).toString()));
        }
        return parts;
    }

    public static List<String> getEmailFromDN(String dn) {
        if (log.isTraceEnabled()) {
            log.trace((Object)(">getEmailFromDN(" + dn + ")"));
        }
        ArrayList<String> ret = new ArrayList<String>();
        for (int i = 0; i < EMAILIDS.length; ++i) {
            List<String> emails = DnComponents.getPartsFromDN(dn, EMAILIDS[i]);
            if (emails.isEmpty()) continue;
            ret.addAll(emails);
        }
        if (log.isTraceEnabled()) {
            log.trace((Object)("<getEmailFromDN(" + dn + "): " + ret.size()));
        }
        return ret;
    }

    public static String getParentDN(String dn) {
        X509NameTokenizer tokenizer = new X509NameTokenizer(dn);
        tokenizer.nextToken();
        return tokenizer.getRemainingString();
    }

    public static String getPartFromDN(String dn, String dnpart) {
        String part = null;
        List<String> dnParts = DnComponents.getPartsFromDNInternal(dn, dnpart, true);
        if (!dnParts.isEmpty()) {
            part = dnParts.get(0);
        }
        return part;
    }

    public static List<String> getPartsFromDN(String dn, String dnpart) {
        return DnComponents.getPartsFromDNInternal(dn, dnpart, false);
    }

    public static String getUnescapedRdnValue(String value) {
        if (StringUtils.isNotEmpty((String)value)) {
            return DnComponents.unescapeRDN(value);
        }
        return value;
    }

    public static List<String> getX500NameComponents(String dn) {
        ArrayList<String> ret = new ArrayList<String>();
        if (StringUtils.isNotBlank((String)dn)) {
            X509NameTokenizer tokenizer = new X509NameTokenizer(dn);
            while (tokenizer.hasMoreTokens()) {
                ret.add(tokenizer.nextToken());
            }
        }
        return ret;
    }

    public static boolean isDNReversed(String dn) {
        boolean ret = false;
        if (dn != null) {
            String first = null;
            String last = null;
            X509NameTokenizer xt = new X509NameTokenizer(dn);
            if (xt.hasMoreTokens()) {
                first = xt.nextToken().trim();
            }
            while (xt.hasMoreTokens()) {
                last = xt.nextToken().trim();
            }
            String[] dNObjects = DnComponents.getDnObjects(true);
            if (first != null && last != null) {
                int fi = first.indexOf(61);
                first = first.substring(0, fi != -1 ? fi : first.length() - 1);
                int li = last.indexOf(61);
                last = last.substring(0, li != -1 ? li : last.length() - 1);
                int firsti = 0;
                int lasti = 0;
                for (int i = 0; i < dNObjects.length; ++i) {
                    if (first.equalsIgnoreCase(dNObjects[i])) {
                        firsti = i;
                    }
                    if (!last.equalsIgnoreCase(dNObjects[i])) continue;
                    lasti = i;
                }
                if (lasti < firsti) {
                    ret = true;
                }
            }
        }
        return ret;
    }

    public static List<ASN1ObjectIdentifier> getX509FieldOrder(boolean ldaporder) {
        return DnComponents.getX509FieldOrder(DnComponents.getDnObjects(ldaporder));
    }

    public static String reverseDN(String dn) {
        if (log.isTraceEnabled()) {
            log.trace((Object)(">reverseDN: dn: " + dn));
        }
        String ret = null;
        if (dn != null) {
            BasicX509NameTokenizer xt = new BasicX509NameTokenizer(dn);
            StringBuilder buf = new StringBuilder();
            boolean first = true;
            while (xt.hasMoreTokens()) {
                String o = xt.nextToken();
                if (!first) {
                    buf.insert(0, ",");
                } else {
                    first = false;
                }
                buf.insert(0, o);
            }
            if (buf.length() > 0) {
                ret = buf.toString();
            }
        }
        if (log.isTraceEnabled()) {
            log.trace((Object)("<reverseDN: resulting dn: " + ret));
        }
        return ret;
    }

    public static X500Name stringToBcX500Name(String dn, X500NameStyle nameStyle, boolean ldaporder, String[] order, boolean applyLdapToCustomOrder) {
        X500Name x500Name = DnComponents.stringToUnorderedX500Name(dn, nameStyle);
        if (x500Name == null) {
            return null;
        }
        X500Name orderedX500Name = DnComponents.getOrderedX500Name(x500Name, ldaporder, order, applyLdapToCustomOrder, nameStyle);
        if (log.isTraceEnabled()) {
            log.trace((Object)(">stringToBcX500Name: x500Name=" + x500Name.toString() + " orderedX500Name=" + orderedX500Name.toString()));
        }
        return orderedX500Name;
    }

    public static X500Name stringToUnorderedX500Name(String dn, X500NameStyle nameStyle) {
        if (log.isTraceEnabled()) {
            log.trace((Object)(">stringToUnorderedX500Name: " + dn));
        }
        if (dn == null) {
            return null;
        }
        if (dn.length() > 2 && dn.charAt(0) == '\"' && dn.charAt(dn.length() - 1) == '\"') {
            dn = dn.substring(1, dn.length() - 1);
        }
        X500NameBuilder nameBuilder = new X500NameBuilder(nameStyle);
        if (dn.length() > 0) {
            RDN[] rdns;
            for (RDN rdn : rdns = IETFUtils.rDNsFromString((String)dn, (X500NameStyle)nameStyle)) {
                if (rdn.isMultiValued()) {
                    AttributeTypeAndValue[] avas = rdn.getTypesAndValues();
                    nameBuilder.addMultiValuedRDN(avas);
                    continue;
                }
                AttributeTypeAndValue ava = rdn.getFirst();
                nameBuilder.addRDN(ava);
            }
        }
        X500Name x500Name = nameBuilder.build();
        if (log.isTraceEnabled()) {
            log.trace((Object)("<stringToUnorderedX500Name: x500Name=" + x500Name.toString()));
        }
        return x500Name;
    }

    public static String stringToBCDNString(String dn) {
        if (DnComponents.isDNReversed(dn)) {
            dn = DnComponents.reverseDN(dn);
        }
        String ret = null;
        X500Name name = DnComponents.stringToBcX500Name(dn);
        if (name != null) {
            ret = name.toString();
        }
        if (ret != null && ret.length() > 250) {
            log.info((Object)("Warning! DN is more than 250 characters long. Some databases have only 250 characters in the database for SubjectDN. Clipping may occur! DN (" + ret.length() + " chars) "));
        }
        return ret;
    }

    public static X500Name stringToBcX500Name(String dn) {
        X500NameStyle nameStyle = CeSecoreNameStyle.INSTANCE;
        return DnComponents.stringToBcX500Name(dn, nameStyle, true);
    }

    public static X500Name stringToBcX500Name(String dn, boolean ldapOrder) {
        X500NameStyle nameStyle = CeSecoreNameStyle.INSTANCE;
        return DnComponents.stringToBcX500Name(dn, nameStyle, ldapOrder);
    }

    public static X500Name stringToBcX500Name(String dn, X500NameStyle nameStyle, boolean ldaporder) {
        return DnComponents.stringToBcX500Name(dn, nameStyle, ldaporder, null);
    }

    public static X500Name stringToBcX500Name(String dn, X500NameStyle nameStyle, boolean ldaporder, String[] order) {
        return DnComponents.stringToBcX500Name(dn, nameStyle, ldaporder, order, true);
    }

    public static String getUnescapedPlus(String value) {
        StringBuilder buf = new StringBuilder(value);
        int end = buf.length();
        for (int index = 0; index < end; ++index) {
            char c;
            if (buf.charAt(index) != '\\' || index + 1 == end || (c = buf.charAt(index + 1)) != '+') continue;
            buf.deleteCharAt(index);
            --end;
        }
        return buf.toString();
    }

    public static GeneralNames getGeneralNamesFromAltName(String altName) {
        if (log.isTraceEnabled()) {
            log.trace((Object)(">getGeneralNamesFromAltName: " + altName));
        }
        if (StringUtils.isNotBlank((String)altName)) {
            return DnComponents.getGeneralNamesFromAltNameInternal(altName);
        }
        return null;
    }

    public static String getUPNAltName(Certificate cert) throws CertificateParsingException {
        return DnComponents.getUTF8AltNameOtherName(cert, UPN_OBJECTID);
    }

    public static String getUTF8AltNameOtherName(Certificate cert, String oid) throws CertificateParsingException {
        String ret;
        block1: {
            List<?> next;
            X509Certificate x509cert;
            Collection<List<?>> altNames;
            ret = null;
            if (!(cert instanceof X509Certificate) || (altNames = (x509cert = (X509Certificate)cert).getSubjectAlternativeNames()) == null) break block1;
            Iterator<List<?>> iterator = altNames.iterator();
            while (iterator.hasNext() && (ret = DnComponents.getUTF8StringFromSequence(DnComponents.getAltnameSequence(next = iterator.next()), oid)) == null) {
            }
        }
        return ret;
    }

    public static String getPermanentIdentifierAltName(Certificate cert) throws CertificateParsingException {
        String ret;
        block1: {
            ASN1Sequence seq;
            X509Certificate x509cert;
            Collection<List<?>> altNames;
            ret = null;
            if (!(cert instanceof X509Certificate) || (altNames = (x509cert = (X509Certificate)cert).getSubjectAlternativeNames()) == null) break block1;
            Iterator<List<?>> i = altNames.iterator();
            while (i.hasNext() && (ret = DnComponents.getPermanentIdentifierStringFromSequence(seq = DnComponents.getAltnameSequence(i.next()))) == null) {
            }
        }
        return ret;
    }

    public static String getHardwareModuleNameAltName(Certificate cert) throws CertificateParsingException {
        String ret;
        block1: {
            ASN1Sequence seq;
            X509Certificate x509cert;
            Collection<List<?>> altNames;
            ret = null;
            if (!(cert instanceof X509Certificate) || (altNames = (x509cert = (X509Certificate)cert).getSubjectAlternativeNames()) == null) break block1;
            Iterator<List<?>> i = altNames.iterator();
            while (i.hasNext() && (ret = DnComponents.getHardwareModuleNameStringFromSequence(seq = DnComponents.getAltnameSequence(i.next()))) == null) {
            }
        }
        return ret;
    }

    public static String getGuidAltName(Certificate cert) throws CertificateParsingException {
        X509Certificate x509cert;
        Collection<List<?>> altNames;
        if (cert instanceof X509Certificate && (altNames = (x509cert = (X509Certificate)cert).getSubjectAlternativeNames()) != null) {
            Iterator<List<?>> i = altNames.iterator();
            while (i.hasNext()) {
                String guid;
                ASN1Sequence seq = DnComponents.getAltnameSequence(i.next());
                if (seq == null || (guid = DnComponents.getGUIDStringFromSequence(seq)) == null) continue;
                return guid;
            }
        }
        return null;
    }

    public static String getSubjectAlternativeName(Certificate certificate) {
        if (log.isTraceEnabled()) {
            log.trace((Object)">getSubjectAlternativeName");
        }
        Object result = "";
        if (certificate instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate)certificate;
            Collection<List<?>> altNames = null;
            try {
                altNames = x509cert.getSubjectAlternativeNames();
            }
            catch (CertificateParsingException e) {
                throw new RuntimeException("Could not parse certificate", e);
            }
            if (altNames == null) {
                return null;
            }
            Iterator<List<?>> iter = altNames.iterator();
            String append = new String();
            List<?> item = null;
            Integer type = null;
            Object value = null;
            while (iter.hasNext()) {
                item = iter.next();
                type = (Integer)item.get(0);
                value = item.get(1);
                if (!StringUtils.isEmpty((String)result)) {
                    append = ", ";
                }
                String rdn = null;
                switch (type) {
                    case 0: {
                        ASN1Sequence sequence = DnComponents.getAltnameSequence(item);
                        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance((Object)sequence.getObjectAt(0));
                        switch (oid.getId()) {
                            case "1.3.6.1.4.1.311.20.2.3": {
                                rdn = "UPN=" + DnComponents.getUTF8StringFromSequence(sequence, UPN_OBJECTID);
                                break;
                            }
                            case "1.3.6.1.5.5.7.8.3": {
                                rdn = "PERMANENTIDENTIFIER=" + DnComponents.getPermanentIdentifierStringFromSequence(sequence);
                                break;
                            }
                            case "1.3.6.1.5.5.7.8.4": {
                                rdn = "HARDWAREMODULENAME=" + DnComponents.getHardwareModuleNameStringFromSequence(sequence);
                                break;
                            }
                            case "1.3.6.1.5.2.2": {
                                rdn = "KRB5PRINCIPAL=" + DnComponents.getKrb5PrincipalNameFromSequence(sequence);
                                break;
                            }
                            case "1.3.6.1.5.5.7.8.6": {
                                String sim = RFC4683Tools.getSimStringSequence(sequence);
                                rdn = "subjectIdentificationMethod=" + sim;
                                break;
                            }
                            case "1.3.6.1.4.1.311.25.1": {
                                rdn = "guid=" + DnComponents.getGUIDStringFromSequence(sequence);
                                break;
                            }
                            case "1.3.6.1.5.5.7.8.5": {
                                rdn = "XMPPADDR=" + DnComponents.getUTF8StringFromSequence(sequence, XMPPADDR_OBJECTID);
                                break;
                            }
                            case "1.3.6.1.5.5.7.8.7": {
                                rdn = "SRVNAME=" + DnComponents.getIA5StringFromSequence(sequence, SRVNAME_OBJECTID);
                                break;
                            }
                            case "2.16.840.1.101.3.6.6": {
                                rdn = "FASCN=" + new String(Hex.encode((byte[])DnComponents.getOctetStringFromSequence(sequence, FASCN_OBJECTID)));
                            }
                        }
                        break;
                    }
                    case 1: {
                        rdn = "rfc822name=" + (String)value;
                        break;
                    }
                    case 2: {
                        rdn = "dNSName=" + (String)value;
                        break;
                    }
                    case 3: {
                        break;
                    }
                    case 4: {
                        rdn = "DIRECTORYNAME=" + (String)value;
                        break;
                    }
                    case 5: {
                        break;
                    }
                    case 6: {
                        rdn = "UNIFORMRESOURCEIDENTIFIER=" + (String)value;
                        break;
                    }
                    case 7: {
                        rdn = "iPAddress=" + (String)value;
                        break;
                    }
                    case 8: {
                        rdn = "REGISTEREDID=" + (String)value;
                        break;
                    }
                }
                if (rdn == null) continue;
                result = (String)result + append + DnComponents.escapeFieldValue(rdn);
            }
            if (log.isTraceEnabled()) {
                log.trace((Object)("<getSubjectAlternativeName: " + (String)result));
            }
            if (StringUtils.isEmpty((String)result)) {
                return null;
            }
        }
        return result;
    }

    public static String getEMailAddress(Certificate certificate) {
        log.debug((Object)"Searching for EMail Address in SubjectAltName");
        if (certificate == null) {
            return null;
        }
        if (certificate instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate)certificate;
            try {
                if (x509cert.getSubjectAlternativeNames() != null) {
                    for (List<?> item : x509cert.getSubjectAlternativeNames()) {
                        Integer type = (Integer)item.get(0);
                        if (type != 1) continue;
                        return (String)item.get(1);
                    }
                }
            }
            catch (CertificateParsingException e) {
                log.error((Object)"Error parsing certificate: ", (Throwable)e);
            }
            log.debug((Object)"Searching for EMail Address in Subject DN");
            List<String> emails = DnComponents.getEmailFromDN(CertTools.getSubjectDN(certificate));
            if (!emails.isEmpty()) {
                return emails.get(0);
            }
        }
        return null;
    }

    public static String getAltNameStringFromExtension(Extension ext) {
        Object altName = null;
        GeneralNames names = DnComponents.getGeneralNamesFromExtension(ext);
        if (names != null) {
            try {
                GeneralName[] gns;
                for (GeneralName gn : gns = names.getNames()) {
                    ASN1Encodable name;
                    int tag = gn.getTagNo();
                    String str = DnComponents.getGeneralNameString(tag, name = gn.getName());
                    if (str == null) continue;
                    altName = altName == null ? DnComponents.escapeFieldValue(str) : (String)altName + ", " + DnComponents.escapeFieldValue(str);
                }
            }
            catch (IOException e) {
                log.error((Object)"IOException parsing altNames: ", (Throwable)e);
                return null;
            }
        }
        return altName;
    }

    public static GeneralNames getGeneralNamesFromExtension(Extension ext) {
        ASN1Encodable gnames = ext.getParsedValue();
        if (gnames != null) {
            GeneralNames names = GeneralNames.getInstance((Object)gnames);
            return names;
        }
        return null;
    }

    public static String getGeneralNameString(int tag, ASN1Encodable value) throws IOException {
        String ret = null;
        switch (tag) {
            case 0: {
                ASN1Sequence sequence = DnComponents.getAltnameSequence(value.toASN1Primitive().getEncoded());
                ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance((Object)sequence.getObjectAt(0));
                switch (oid.getId()) {
                    case "1.3.6.1.4.1.311.20.2.3": {
                        ret = "UPN=" + DnComponents.getUTF8StringFromSequence(sequence, UPN_OBJECTID);
                        break;
                    }
                    case "1.3.6.1.5.5.7.8.3": {
                        ret = "PERMANENTIDENTIFIER=" + DnComponents.getPermanentIdentifierStringFromSequence(sequence);
                        break;
                    }
                    case "1.3.6.1.5.5.7.8.4": {
                        ret = "HARDWAREMODULENAME=" + DnComponents.getHardwareModuleNameStringFromSequence(sequence);
                        break;
                    }
                    case "1.3.6.1.5.2.2": {
                        ret = "KRB5PRINCIPAL=" + DnComponents.getKrb5PrincipalNameFromSequence(sequence);
                        break;
                    }
                    case "1.3.6.1.5.5.7.8.6": {
                        ret = "subjectIdentificationMethod=" + RFC4683Tools.getSimStringSequence(sequence);
                        break;
                    }
                    case "1.3.6.1.5.5.7.8.5": {
                        ret = "XMPPADDR=" + DnComponents.getUTF8StringFromSequence(sequence, XMPPADDR_OBJECTID);
                        break;
                    }
                    case "1.3.6.1.5.5.7.8.7": {
                        ret = "SRVNAME=" + DnComponents.getIA5StringFromSequence(sequence, SRVNAME_OBJECTID);
                        break;
                    }
                    case "2.16.840.1.101.3.6.6": {
                        ret = "FASCN=" + new String(Hex.encode((byte[])DnComponents.getOctetStringFromSequence(sequence, FASCN_OBJECTID)));
                        break;
                    }
                    case "1.3.6.1.4.1.311.25.1": {
                        ret = "GUID=" + DnComponents.getGUIDStringFromSequence(sequence);
                    }
                }
                break;
            }
            case 1: {
                ret = "rfc822name=" + ASN1IA5String.getInstance((Object)value).getString();
                break;
            }
            case 2: {
                ret = "dNSName=" + ASN1IA5String.getInstance((Object)value).getString();
                break;
            }
            case 3: {
                break;
            }
            case 4: {
                X500Name name = X500Name.getInstance((Object)value);
                ret = "DIRECTORYNAME=" + name.toString();
                break;
            }
            case 5: {
                break;
            }
            case 6: {
                ret = "UNIFORMRESOURCEIDENTIFIER=" + ASN1IA5String.getInstance((Object)value).getString();
                break;
            }
            case 7: {
                ASN1OctetString oct = ASN1OctetString.getInstance((Object)value);
                String parsedIP = StringTools.ipOctetsToString(oct.getOctets());
                if (parsedIP == null) {
                    parsedIP = StringTools.isIpV6Address(StringTools.convertToIpv6(value.toString())) ? StringTools.convertToIpv6(value.toString()) : null;
                }
                ret = "iPAddress=" + parsedIP;
                break;
            }
            case 8: {
                ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance((Object)value);
                ret = "registeredID=" + oid.getId();
                break;
            }
        }
        return ret;
    }

    private static byte[] getOctetStringFromSequence(ASN1Sequence seq, String oid) {
        ASN1ObjectIdentifier id;
        if (seq != null && (id = ASN1ObjectIdentifier.getInstance((Object)seq.getObjectAt(0))).getId().equals(oid)) {
            ASN1TaggedObject oobj = ASN1TaggedObject.getInstance((Object)seq.getObjectAt(1));
            ASN1Primitive obj = oobj.getBaseObject().toASN1Primitive();
            if (obj instanceof ASN1TaggedObject) {
                obj = ASN1TaggedObject.getInstance((Object)obj).getBaseObject().toASN1Primitive();
            }
            ASN1OctetString str = ASN1OctetString.getInstance((Object)obj);
            return str.getOctets();
        }
        return null;
    }

    private static String getIA5StringFromSequence(ASN1Sequence seq, String oid) {
        ASN1ObjectIdentifier id;
        if (seq != null && (id = ASN1ObjectIdentifier.getInstance((Object)seq.getObjectAt(0))).getId().equals(oid)) {
            ASN1TaggedObject oobj = ASN1TaggedObject.getInstance((Object)seq.getObjectAt(1));
            ASN1Primitive obj = oobj.getBaseObject().toASN1Primitive();
            if (obj instanceof ASN1TaggedObject) {
                obj = ASN1TaggedObject.getInstance((Object)obj).getBaseObject().toASN1Primitive();
            }
            ASN1IA5String str = ASN1IA5String.getInstance((Object)obj);
            return str.getString();
        }
        return null;
    }

    private static String unescapeFieldValue(String value) {
        if (value == null) {
            return null;
        }
        return UNESCAPE_FIELD_REGEX.matcher(value).replaceAll("$1");
    }

    private static String escapeFieldValue(String value) {
        if (value == null) {
            return null;
        }
        if (value.indexOf(61) == value.length() - 1) {
            return value;
        }
        return DnComponents.escapeRDN(value);
    }

    private static String escapeRDN(String rdn) {
        int i;
        StringBuffer escapedS = new StringBuffer(rdn);
        for (i = 0; i < escapedS.length() && escapedS.charAt(i) != '='; ++i) {
        }
        if (i == escapedS.length()) {
            throw new IllegalArgumentException("Could not parse RDN: Attribute type and name must be separated by an equal symbol, '='");
        }
        if (escapedS.charAt(++i) == ' ' || escapedS.charAt(i) == '#') {
            escapedS.insert(i++, '\\');
        }
        while (i < escapedS.length()) {
            if (escapedS.charAt(i) == ',' || escapedS.charAt(i) == '+' || escapedS.charAt(i) == '\"' || escapedS.charAt(i) == '\\' || escapedS.charAt(i) == '<' || escapedS.charAt(i) == '>' || escapedS.charAt(i) == ';') {
                escapedS.insert(i++, '\\');
            }
            ++i;
        }
        if (escapedS.charAt(escapedS.length() - 1) == ' ') {
            escapedS.insert(escapedS.length() - 1, '\\');
        }
        return escapedS.toString();
    }

    private static String getKrb5PrincipalNameFromSequence(ASN1Sequence seq) {
        ASN1ObjectIdentifier id;
        Object ret = null;
        if (seq != null && (id = ASN1ObjectIdentifier.getInstance((Object)seq.getObjectAt(0))).getId().equals(KRB5PRINCIPAL_OBJECTID)) {
            ASN1TaggedObject oobj = ASN1TaggedObject.getInstance((Object)seq.getObjectAt(1));
            ASN1Primitive obj = oobj.getBaseObject().toASN1Primitive();
            if (obj instanceof ASN1TaggedObject) {
                obj = ASN1TaggedObject.getInstance((Object)obj).getBaseObject().toASN1Primitive();
            }
            ASN1Sequence krb5Seq = ASN1Sequence.getInstance((Object)obj);
            ASN1TaggedObject robj = ASN1TaggedObject.getInstance((Object)krb5Seq.getObjectAt(0));
            ASN1GeneralString realmObj = ASN1GeneralString.getInstance((Object)robj.getBaseObject().toASN1Primitive());
            String realm = realmObj.getString();
            ASN1TaggedObject pobj = ASN1TaggedObject.getInstance((Object)krb5Seq.getObjectAt(1));
            ASN1Sequence nseq = ASN1Sequence.getInstance((Object)pobj.getBaseObject().toASN1Primitive());
            ASN1TaggedObject nobj = ASN1TaggedObject.getInstance((Object)nseq.getObjectAt(1));
            ASN1Sequence sseq = ASN1Sequence.getInstance((Object)nobj.getBaseObject().toASN1Primitive());
            Enumeration en = sseq.getObjects();
            while (en.hasMoreElements()) {
                ASN1GeneralString str = ASN1GeneralString.getInstance(en.nextElement());
                if (ret != null) {
                    ret = (String)ret + "/" + str.getString();
                    continue;
                }
                ret = str.getString();
            }
            ret = ret + "@" + realm;
        }
        return ret;
    }

    private static String getGUIDStringFromSequence(ASN1Sequence seq) {
        ASN1ObjectIdentifier id;
        String ret = null;
        if (seq != null && (id = ASN1ObjectIdentifier.getInstance((Object)seq.getObjectAt(0))).getId().equals(GUID_OBJECTID)) {
            ASN1TaggedObject oobj = ASN1TaggedObject.getInstance((Object)seq.getObjectAt(1));
            ASN1Primitive obj = oobj.getBaseObject().toASN1Primitive();
            if (obj instanceof ASN1TaggedObject) {
                obj = ASN1TaggedObject.getInstance((Object)obj).getBaseObject().toASN1Primitive();
            }
            ASN1OctetString str = ASN1OctetString.getInstance((Object)obj);
            ret = new String(Hex.encode((byte[])str.getOctets()));
        }
        return ret;
    }

    private static String getUTF8StringFromSequence(ASN1Sequence seq, String oid) {
        ASN1ObjectIdentifier id;
        if (seq != null && (id = ASN1ObjectIdentifier.getInstance((Object)seq.getObjectAt(0))).getId().equals(oid)) {
            ASN1TaggedObject oobj = ASN1TaggedObject.getInstance((Object)seq.getObjectAt(1));
            ASN1Primitive obj = oobj.getBaseObject().toASN1Primitive();
            if (obj instanceof ASN1TaggedObject) {
                obj = ASN1TaggedObject.getInstance((Object)obj).getBaseObject().toASN1Primitive();
            }
            ASN1UTF8String str = ASN1UTF8String.getInstance((Object)obj);
            return str.getString();
        }
        return null;
    }

    private static String getPermanentIdentifierStringFromSequence(ASN1Sequence seq) {
        ASN1ObjectIdentifier id;
        if (seq != null && (id = ASN1ObjectIdentifier.getInstance((Object)seq.getObjectAt(0))).getId().equals(PERMANENTIDENTIFIER_OBJECTID)) {
            ASN1Sequence piSeq;
            Enumeration e;
            String identifierValue = null;
            String assigner = null;
            ASN1TaggedObject oobj = ASN1TaggedObject.getInstance((Object)seq.getObjectAt(1));
            ASN1Primitive obj = oobj.getBaseObject().toASN1Primitive();
            if (obj instanceof ASN1TaggedObject) {
                obj = ASN1TaggedObject.getInstance((Object)obj).getBaseObject().toASN1Primitive();
            }
            if ((e = (piSeq = ASN1Sequence.getInstance((Object)obj)).getObjects()).hasMoreElements()) {
                Object element = e.nextElement();
                if (element instanceof DERUTF8String) {
                    identifierValue = ((DERUTF8String)element).getString();
                    if (e.hasMoreElements()) {
                        element = e.nextElement();
                    }
                }
                if (element instanceof ASN1ObjectIdentifier) {
                    assigner = ((ASN1ObjectIdentifier)element).getId();
                }
            }
            StringBuilder buff = new StringBuilder();
            if (identifierValue != null) {
                buff.append(DnComponents.escapePermanentIdentifierValue(identifierValue));
            }
            buff.append("/");
            if (assigner != null) {
                buff.append(assigner);
            }
            return buff.toString();
        }
        return null;
    }

    public static String getHardwareModuleNameStringFromSequence(ASN1Sequence seq) {
        ASN1ObjectIdentifier id;
        if (seq != null && (id = ASN1ObjectIdentifier.getInstance((Object)seq.getObjectAt(0))).getId().equals(HARDWAREMODULENAME_OBJECTID)) {
            Object element;
            ASN1Sequence hwName;
            Enumeration e;
            String hwType = null;
            String hwSerialNum = null;
            ASN1TaggedObject oobj = ASN1TaggedObject.getInstance((Object)seq.getObjectAt(1));
            ASN1Primitive obj = oobj.getBaseObject().toASN1Primitive();
            if (obj instanceof ASN1TaggedObject) {
                obj = ASN1TaggedObject.getInstance((Object)obj).getBaseObject().toASN1Primitive();
            }
            if ((e = (hwName = ASN1Sequence.getInstance((Object)obj)).getObjects()).hasMoreElements() && (element = e.nextElement()) instanceof ASN1ObjectIdentifier) {
                hwType = ((ASN1ObjectIdentifier)element).getId();
            }
            if (e.hasMoreElements() && (element = e.nextElement()) instanceof DEROctetString) {
                hwSerialNum = new String(((DEROctetString)element).getOctets(), StandardCharsets.US_ASCII);
            }
            StringBuilder buff = new StringBuilder();
            buff.append(hwType);
            if (hwSerialNum != null) {
                buff.append("/");
                buff.append(hwSerialNum);
            }
            return buff.toString();
        }
        return null;
    }

    private static String escapePermanentIdentifierValue(String realValue) {
        return realValue.replace("/", "\\/");
    }

    private static ASN1Sequence getAltnameSequence(List<?> listitem) {
        Integer no = (Integer)listitem.get(0);
        if (no == 0) {
            byte[] altName = (byte[])listitem.get(1);
            return DnComponents.getAltnameSequence(altName);
        }
        return null;
    }

    private static ASN1Sequence getAltnameSequence(byte[] value) {
        ASN1Primitive oct = null;
        try {
            oct = ASN1Primitive.fromByteArray((byte[])value);
        }
        catch (IOException e) {
            throw new IllegalArgumentException("Could not read ASN1InputStream", e);
        }
        if (oct instanceof ASN1TaggedObject) {
            oct = ((ASN1TaggedObject)oct).getBaseObject().toASN1Primitive();
        }
        ASN1Sequence seq = ASN1Sequence.getInstance((Object)oct);
        return seq;
    }

    private static GeneralNames getGeneralNamesFromAltNameInternal(String altName) {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        String[] result = altName.split("(?<!\\\\),");
        block40: for (String str : result) {
            String[] subResult = str.trim().split("=");
            switch (subResult[0].trim().toUpperCase()) {
                case "EMAILADDRESS": 
                case "RFC822NAME": {
                    for (String email : DnComponents.getEmailFromDN(str)) {
                        vec.add((ASN1Encodable)new GeneralName(1, email));
                    }
                    continue block40;
                }
                case "IPADDRESS": {
                    for (String addr : DnComponents.getPartsFromDN(str, IPADDR)) {
                        byte[] ipoctets = StringTools.ipStringToOctets(addr);
                        if (ipoctets.length > 0) {
                            GeneralName gn = new GeneralName(7, (ASN1Encodable)new DEROctetString(ipoctets));
                            vec.add((ASN1Encodable)gn);
                            continue;
                        }
                        log.error((Object)("Cannot parse/encode ip address, ignoring: " + addr));
                    }
                    continue block40;
                }
                case "DNSNAME": {
                    for (String dns : DnComponents.getPartsFromDN(str, DNS)) {
                        vec.add((ASN1Encodable)new GeneralName(2, (ASN1Encodable)new DERIA5String(dns)));
                    }
                    continue block40;
                }
                case "DIRECTORYNAME": {
                    String directoryName = DnComponents.getDirectoryStringFromAltName(str);
                    if (directoryName == null) continue block40;
                    X500Name x500DirectoryName = new X500Name(CeSecoreNameStyle.INSTANCE, directoryName);
                    GeneralName gn = new GeneralName(4, (ASN1Encodable)x500DirectoryName);
                    vec.add((ASN1Encodable)gn);
                    continue block40;
                }
                case "UNIFORMRESOURCEIDENTIFIER": {
                    for (String uri : DnComponents.getPartsFromDN(str, URI)) {
                        vec.add((ASN1Encodable)new GeneralName(6, (ASN1Encodable)new DERIA5String(uri)));
                    }
                    continue block40;
                }
                case "URI": {
                    for (String uri : DnComponents.getPartsFromDN(str, URI1)) {
                        vec.add((ASN1Encodable)new GeneralName(6, (ASN1Encodable)new DERIA5String(uri)));
                    }
                    continue block40;
                }
                case "UNIFORMRESOURCEID": {
                    for (String uri : DnComponents.getPartsFromDN(str, URI2)) {
                        vec.add((ASN1Encodable)new GeneralName(6, (ASN1Encodable)new DERIA5String(uri)));
                    }
                    continue block40;
                }
                case "REGISTEREDID": {
                    for (String oid : DnComponents.getPartsFromDN(str, REGISTEREDID)) {
                        vec.add((ASN1Encodable)new GeneralName(8, oid));
                    }
                    continue block40;
                }
                case "UPN": {
                    for (String upn : DnComponents.getPartsFromDN(str, UPN)) {
                        ASN1EncodableVector v = new ASN1EncodableVector();
                        v.add((ASN1Encodable)new ASN1ObjectIdentifier(UPN_OBJECTID));
                        v.add((ASN1Encodable)new DERTaggedObject(true, 0, (ASN1Encodable)new DERUTF8String(upn)));
                        vec.add((ASN1Encodable)GeneralName.getInstance((Object)new DERTaggedObject(false, 0, (ASN1Encodable)new DERSequence(v))));
                    }
                    continue block40;
                }
                case "XMPPADDR": {
                    for (String xmppAddr : DnComponents.getPartsFromDN(str, XMPPADDR)) {
                        ASN1EncodableVector v = new ASN1EncodableVector();
                        v.add((ASN1Encodable)new ASN1ObjectIdentifier(XMPPADDR_OBJECTID));
                        v.add((ASN1Encodable)new DERTaggedObject(true, 0, (ASN1Encodable)new DERUTF8String(xmppAddr)));
                        vec.add((ASN1Encodable)GeneralName.getInstance((Object)new DERTaggedObject(false, 0, (ASN1Encodable)new DERSequence(v))));
                    }
                    continue block40;
                }
                case "SRVNAME": {
                    for (String srvName : DnComponents.getPartsFromDN(str, SRVNAME)) {
                        ASN1EncodableVector v = new ASN1EncodableVector();
                        v.add((ASN1Encodable)new ASN1ObjectIdentifier(SRVNAME_OBJECTID));
                        v.add((ASN1Encodable)new DERTaggedObject(true, 0, (ASN1Encodable)new DERIA5String(srvName)));
                        vec.add((ASN1Encodable)GeneralName.getInstance((Object)new DERTaggedObject(false, 0, (ASN1Encodable)new DERSequence(v))));
                    }
                    continue block40;
                }
                case "FASCN": {
                    for (String fascN : DnComponents.getPartsFromDN(str, FASCN)) {
                        ASN1EncodableVector v = new ASN1EncodableVector();
                        v.add((ASN1Encodable)new ASN1ObjectIdentifier(FASCN_OBJECTID));
                        v.add((ASN1Encodable)new DERTaggedObject(true, 0, (ASN1Encodable)new DEROctetString(Hex.decode((String)fascN))));
                        vec.add((ASN1Encodable)GeneralName.getInstance((Object)new DERTaggedObject(false, 0, (ASN1Encodable)new DERSequence(v))));
                    }
                    continue block40;
                }
                case "PERMANENTIDENTIFIER": {
                    for (String permanentIdentifier : DnComponents.getPartsFromDN(str, PERMANENTIDENTIFIER)) {
                        String[] values = DnComponents.getPermanentIdentifierValues(permanentIdentifier);
                        ASN1EncodableVector v = new ASN1EncodableVector();
                        v.add((ASN1Encodable)new ASN1ObjectIdentifier(PERMANENTIDENTIFIER_OBJECTID));
                        ASN1EncodableVector piSeq = new ASN1EncodableVector();
                        if (values[0] != null) {
                            piSeq.add((ASN1Encodable)new DERUTF8String(values[0]));
                        }
                        if (values[1] != null) {
                            piSeq.add((ASN1Encodable)new ASN1ObjectIdentifier(values[1]));
                        }
                        v.add((ASN1Encodable)new DERTaggedObject(true, 0, (ASN1Encodable)new DERSequence(piSeq)));
                        DERTaggedObject gn = new DERTaggedObject(false, 0, (ASN1Encodable)new DERSequence(v));
                        vec.add((ASN1Encodable)gn);
                    }
                    continue block40;
                }
                case "HARDWAREMODULENAME": {
                    for (String hwn : DnComponents.getPartsFromDN(str, HARDWAREMODULENAME)) {
                        String type = hwn.substring(0, hwn.indexOf(47));
                        String serial = hwn.substring(hwn.indexOf(47) + 1, hwn.length());
                        DERTaggedObject gn = new DERTaggedObject(false, 0, (ASN1Encodable)DnComponents.hardwareModuleName(type, serial));
                        vec.add((ASN1Encodable)gn);
                    }
                    continue block40;
                }
                case "GUID": {
                    for (String guid : DnComponents.getPartsFromDN(str, GUID)) {
                        ASN1EncodableVector v = new ASN1EncodableVector();
                        String dashRemovedGuid = guid.replace("-", "");
                        byte[] guidbytes = Hex.decode((String)dashRemovedGuid);
                        if (guidbytes != null) {
                            v.add((ASN1Encodable)new ASN1ObjectIdentifier(GUID_OBJECTID));
                            v.add((ASN1Encodable)new DERTaggedObject(true, 0, (ASN1Encodable)new DEROctetString(guidbytes)));
                            DERTaggedObject gn = new DERTaggedObject(false, 0, (ASN1Encodable)new DERSequence(v));
                            vec.add((ASN1Encodable)gn);
                            continue;
                        }
                        log.error((Object)("Cannot decode hexadecimal guid, ignoring: " + guid));
                    }
                    continue block40;
                }
                case "KRB5PRINCIPAL": {
                    for (String principalString : DnComponents.getPartsFromDN(str, KRB5PRINCIPAL)) {
                        if (log.isDebugEnabled()) {
                            log.debug((Object)("principalString: " + principalString));
                        }
                        int index = principalString.lastIndexOf(64);
                        String realm = "";
                        if (index > 0) {
                            realm = principalString.substring(index + 1);
                        }
                        if (log.isDebugEnabled()) {
                            log.debug((Object)("realm: " + realm));
                        }
                        ArrayList<String> principalarr = new ArrayList<String>();
                        int jndex = 0;
                        int bindex = 0;
                        while (jndex < index) {
                            jndex = principalString.indexOf(47, bindex);
                            if (jndex == -1) {
                                jndex = index;
                            }
                            String s = principalString.substring(bindex, jndex);
                            if (log.isDebugEnabled()) {
                                log.debug((Object)("adding principal name: " + s));
                            }
                            principalarr.add(s);
                            bindex = jndex + 1;
                        }
                        ASN1EncodableVector v = new ASN1EncodableVector();
                        v.add((ASN1Encodable)new ASN1ObjectIdentifier(KRB5PRINCIPAL_OBJECTID));
                        ASN1EncodableVector krb5p = new ASN1EncodableVector();
                        krb5p.add((ASN1Encodable)new DERTaggedObject(true, 0, (ASN1Encodable)new DERGeneralString(realm)));
                        ASN1EncodableVector principals = new ASN1EncodableVector();
                        principals.add((ASN1Encodable)new DERTaggedObject(true, 0, (ASN1Encodable)new ASN1Integer(0L)));
                        ASN1EncodableVector names = new ASN1EncodableVector();
                        for (String principalName : principalarr) {
                            names.add((ASN1Encodable)new DERGeneralString(principalName));
                        }
                        principals.add((ASN1Encodable)new DERTaggedObject(true, 1, (ASN1Encodable)new DERSequence(names)));
                        krb5p.add((ASN1Encodable)new DERTaggedObject(true, 1, (ASN1Encodable)new DERSequence(principals)));
                        v.add((ASN1Encodable)new DERTaggedObject(true, 0, (ASN1Encodable)new DERSequence(krb5p)));
                        DERTaggedObject gn = new DERTaggedObject(false, 0, (ASN1Encodable)new DERSequence(v));
                        vec.add((ASN1Encodable)gn);
                    }
                    continue block40;
                }
                case "SUBJECTIDENTIFICATIONMETHOD": 
                case "subjectIdentificationMethod": {
                    for (String internalSimString : DnComponents.getPartsFromDN(str, "subjectIdentificationMethod")) {
                        String[] tokens;
                        if (!StringUtils.isNotBlank((String)internalSimString) || (tokens = internalSimString.split("::")).length != 3) continue;
                        ASN1Primitive gn = RFC4683Tools.createSimGeneralName(tokens[0], tokens[1], tokens[2]);
                        vec.add((ASN1Encodable)gn);
                        if (!log.isDebugEnabled()) continue;
                        log.debug((Object)("SIM GeneralName added: " + gn.toString()));
                    }
                    continue block40;
                }
                default: {
                    log.info((Object)("Unknown SAN tag encountered!" + subResult[0]));
                }
            }
        }
        for (String oid : DnComponents.getCustomOids(altName)) {
            for (String oidValue : DnComponents.getPartsFromDN(altName, oid)) {
                ASN1EncodableVector v = new ASN1EncodableVector();
                v.add((ASN1Encodable)new ASN1ObjectIdentifier(oid));
                v.add((ASN1Encodable)new DERTaggedObject(true, 0, (ASN1Encodable)new DERUTF8String(oidValue)));
                DERTaggedObject gn = new DERTaggedObject(false, 0, (ASN1Encodable)new DERSequence(v));
                vec.add((ASN1Encodable)gn);
            }
        }
        if (vec.size() > 0) {
            return GeneralNames.getInstance((Object)new DERSequence(vec));
        }
        return null;
    }

    public static DERSequence hardwareModuleName(String hwType, String hwSerialNum) {
        ASN1EncodableVector otherName = new ASN1EncodableVector();
        otherName.add((ASN1Encodable)new ASN1ObjectIdentifier(HARDWAREMODULENAME_OBJECTID));
        ASN1EncodableVector hwName = new ASN1EncodableVector();
        if (hwType != null) {
            hwName.add((ASN1Encodable)new ASN1ObjectIdentifier(hwType));
        }
        if (hwSerialNum != null) {
            hwName.add((ASN1Encodable)new DEROctetString(hwSerialNum.getBytes(StandardCharsets.US_ASCII)));
        }
        otherName.add((ASN1Encodable)new DERTaggedObject(true, 0, (ASN1Encodable)new DERSequence(hwName)));
        return new DERSequence(otherName);
    }

    private static String unescapePermanentIdentifierValue(String escapedValue) {
        return escapedValue.replace("\\PERMANENTIDENTIFIER", PERMANENTIDENTIFIER);
    }

    private static String[] getPermanentIdentifierValues(String permanentIdentifierString) {
        String[] result = new String[2];
        int sepPos = permanentIdentifierString.lastIndexOf("/");
        if (sepPos == -1) {
            if (!permanentIdentifierString.isEmpty()) {
                result[0] = DnComponents.unescapePermanentIdentifierValue(permanentIdentifierString);
            }
        } else if (sepPos == 0) {
            if (permanentIdentifierString.length() > 1) {
                result[1] = permanentIdentifierString.substring(1);
            }
        } else if (permanentIdentifierString.charAt(sepPos - "/".length()) != '\\') {
            result[0] = DnComponents.unescapePermanentIdentifierValue(permanentIdentifierString.substring(0, sepPos));
            if (permanentIdentifierString.length() > sepPos + "/".length()) {
                result[1] = permanentIdentifierString.substring(sepPos + 1);
            }
        }
        return result;
    }

    private static String getDirectoryStringFromAltName(String altName) {
        String directoryName = DnComponents.getPartFromDN(altName, DIRECTORYNAME);
        return "".equals(directoryName) ? null : directoryName;
    }

    private static X500Name getOrderedX500Name(X500Name x500Name, boolean ldaporder, String[] order, boolean applyLdapToCustomOrder, X500NameStyle nameStyle) {
        List<ASN1ObjectIdentifier> ordering;
        boolean useCustomOrder;
        boolean isLdapOrder = !DnComponents.isDNReversed(x500Name.toString());
        boolean bl = useCustomOrder = order != null && order.length > 0;
        if (useCustomOrder) {
            log.debug((Object)"Using custom DN order");
            ordering = DnComponents.getX509FieldOrder(order);
        } else {
            ordering = DnComponents.getX509FieldOrder(isLdapOrder);
        }
        ArrayList<ASN1ObjectIdentifier> newOrdering = new ArrayList<ASN1ObjectIdentifier>();
        ArrayList<RDN> newValues = new ArrayList<RDN>();
        RDN[] allRdns = x500Name.getRDNs();
        HashSet<ASN1ObjectIdentifier> hs = new HashSet<ASN1ObjectIdentifier>(allRdns.length + ordering.size());
        for (ASN1ObjectIdentifier oid : ordering) {
            if (hs.contains(oid)) continue;
            hs.add(oid);
            for (RDN value : allRdns) {
                if (!oid.equals((ASN1Primitive)value.getFirst().getType())) continue;
                newOrdering.add(oid);
                newValues.add(value);
            }
        }
        for (RDN rdn : allRdns) {
            RDN[] valueList;
            ASN1ObjectIdentifier oid = rdn.getFirst().getType();
            if (hs.contains(oid)) continue;
            hs.add(oid);
            for (RDN value : valueList = x500Name.getRDNs(oid)) {
                newOrdering.add(oid);
                newValues.add(value);
                if (!log.isDebugEnabled()) continue;
                log.debug((Object)("added --> " + oid + " val: " + value));
            }
        }
        if ((useCustomOrder && applyLdapToCustomOrder || !useCustomOrder) && ldaporder != isLdapOrder) {
            if (log.isDebugEnabled()) {
                log.debug((Object)("Reversing order of DN, ldaporder=" + ldaporder + ", isLdapOrder=" + isLdapOrder));
            }
            Collections.reverse(newOrdering);
            Collections.reverse(newValues);
        }
        X500NameBuilder nameBuilder = new X500NameBuilder(nameStyle);
        for (int i = 0; i < newOrdering.size(); ++i) {
            RDN rdn = (RDN)newValues.get(i);
            if (rdn.isMultiValued()) {
                AttributeTypeAndValue[] avas = rdn.getTypesAndValues();
                if (log.isDebugEnabled()) {
                    log.debug((Object)("Multi-value RDN with " + avas.length + " number of values in it."));
                }
                nameBuilder.addMultiValuedRDN(avas);
                continue;
            }
            nameBuilder.addRDN((ASN1ObjectIdentifier)newOrdering.get(i), rdn.getFirst().getValue());
        }
        return nameBuilder.build();
    }

    private static List<String> getPartsFromDNInternal(String dn, String dnPart, boolean onlyReturnFirstMatch) {
        if (log.isTraceEnabled()) {
            log.trace((Object)(">getPartsFromDNInternal: dn:'" + dn + "', dnpart=" + dnPart + ", onlyReturnFirstMatch=" + onlyReturnFirstMatch));
        }
        ArrayList<String> parts = new ArrayList<String>();
        if (dn != null && dnPart != null) {
            String dnPartLowerCase = dnPart.toLowerCase();
            int dnPartLenght = dnPart.length();
            boolean quoted = false;
            boolean escapeNext = false;
            int currentStartPosition = -1;
            for (int i = 0; i < dn.length(); ++i) {
                char current = dn.charAt(i);
                if (!escapeNext && current == '\"') {
                    boolean bl = quoted = !quoted;
                }
                if (!(quoted || escapeNext || current != '=' || dnPartLenght > i || i - dnPartLenght - 1 >= 0 && Character.isLetter(dn.charAt(i - dnPartLenght - 1)))) {
                    boolean match = true;
                    for (int j = 0; j < dnPartLenght; ++j) {
                        if (Character.toLowerCase(dn.charAt(i - dnPartLenght + j)) == dnPartLowerCase.charAt(j)) continue;
                        match = false;
                        break;
                    }
                    if (match) {
                        currentStartPosition = i + 1;
                    }
                }
                if (!(currentStartPosition == -1 || (quoted || escapeNext || current != ',' && current != '+') && i != dn.length() - 1)) {
                    int endPosition;
                    int n = endPosition = i == dn.length() - 1 ? dn.length() - 1 : i - 1;
                    while (endPosition > currentStartPosition && dn.charAt(endPosition) == ' ') {
                        --endPosition;
                    }
                    while (endPosition > currentStartPosition && dn.charAt(currentStartPosition) == ' ') {
                        ++currentStartPosition;
                    }
                    if (currentStartPosition != dn.length() && dn.charAt(currentStartPosition) == '\"' && dn.charAt(endPosition) == '\"') {
                        ++currentStartPosition;
                        --endPosition;
                    }
                    parts.add(DnComponents.unescapeFieldValue(dn.substring(currentStartPosition, endPosition + 1)));
                    if (onlyReturnFirstMatch) break;
                    currentStartPosition = -1;
                }
                if (escapeNext) {
                    escapeNext = false;
                    continue;
                }
                if (quoted || current != '\\') continue;
                escapeNext = true;
            }
        }
        if (log.isTraceEnabled()) {
            log.trace((Object)("<getPartsFromDNInternal: resulting DN part=" + ((Object)parts).toString()));
        }
        return parts;
    }

    private static String unescapeRDN(String rdn) {
        int i;
        StringBuffer unescaped = new StringBuffer();
        for (i = 0; i < rdn.length() && rdn.charAt(i) != '='; ++i) {
            unescaped.append(rdn.charAt(i));
        }
        unescaped.append(rdn.charAt(i));
        if (i == rdn.length()) {
            throw new IllegalArgumentException("Could not parse rdn: Attribute type and name must be separated by an equal symbol, '='");
        }
        if (rdn.charAt(++i) == '\\' && i + 1 < rdn.length() - 1 && (rdn.charAt(i + 1) == ' ' || rdn.charAt(i + 1) == '#')) {
            ++i;
        }
        while (i < rdn.length()) {
            block9: {
                block7: {
                    block8: {
                        if (rdn.charAt(i) != '\\' || i == rdn.length() - 1) break block7;
                        if (rdn.charAt(i + 1) != ',' && rdn.charAt(i + 1) != '+' && rdn.charAt(i + 1) != '\"' && rdn.charAt(i + 1) != '\\' && rdn.charAt(i + 1) != '<' && rdn.charAt(i + 1) != '>' && rdn.charAt(i + 1) != ';') break block8;
                        unescaped.append(rdn.charAt(i + 1));
                        ++i;
                        break block9;
                    }
                    if (rdn.charAt(i + 1) == ' ' && i + 2 == rdn.length()) break block9;
                }
                unescaped.append(rdn.charAt(i));
            }
            ++i;
        }
        return unescaped.toString();
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private static void loadProfileMappingsFromFile(String propertiesFile) {
        BufferedReader in = null;
        InputStreamReader inf = null;
        try {
            InputStream is = obj.getClass().getResourceAsStream(propertiesFile);
            if (is != null) {
                String line;
                inf = new InputStreamReader(is);
                in = new BufferedReader(inf);
                if (!in.ready()) {
                    throw new IOException("Couldn't read " + propertiesFile);
                }
                String[] splits = null;
                int lines = 0;
                ArrayList<Integer> dnids = new ArrayList<Integer>();
                ArrayList<Integer> profileids = new ArrayList<Integer>();
                while ((line = in.readLine()) != null) {
                    if (line.startsWith("#") || (splits = StringUtils.split((String)line, (char)';')) == null || splits.length <= 5) continue;
                    String type = splits[0];
                    String dnname = splits[1];
                    Integer dnid = Integer.valueOf(splits[2]);
                    String profilename = splits[3];
                    Integer profileid = Integer.valueOf(splits[4]);
                    String errstr = splits[5];
                    String langstr = splits[6];
                    if (dnids.contains(dnid)) {
                        log.error((Object)("Duplicated DN Id " + dnid + " detected in mapping file."));
                    } else {
                        dnids.add(dnid);
                    }
                    if (profileids.contains(profileid)) {
                        log.error((Object)("Duplicated Profile Id " + profileid + " detected in mapping file."));
                    } else {
                        profileids.add(profileid);
                    }
                    profileNameIdMap.put(profilename, profileid);
                    dnIdToProfileNameMap.put(dnid, profilename);
                    dnIdToProfileIdMap.put(dnid, profileid);
                    dnIdErrorMap.put(dnid, errstr);
                    profileIdToDnIdMap.put(profileid, dnid);
                    dnErrorTextMap.put(dnid, errstr);
                    profileNameLanguageMap.put(profilename, langstr);
                    profileIdLanguageMap.put(profileid, langstr);
                    if (type.equals("DN")) {
                        dnNameToIdMap.put(dnname, dnid);
                        dnProfileFields.add(profilename);
                        dnProfileFieldsHashSet.add(profilename);
                        dnLanguageTexts.add(langstr);
                        dnDnIds.add(dnid);
                        dnExtractorFields.add(dnname + "=");
                        dnIdToExtractorFieldMap.put(dnid, dnname + "=");
                    }
                    if (type.equals("ALTNAME")) {
                        altNameToIdMap.put(dnname, dnid);
                        altNameFields.add(dnname);
                        altNameFieldsHashSet.add(dnname);
                        altNameLanguageTexts.add(langstr);
                        altNameDnIds.add(dnid);
                        altNameExtractorFields.add(dnname + "=");
                        altNameIdToExtractorFieldMap.put(dnid, dnname + "=");
                    }
                    if (type.equals("DIRATTR")) {
                        dirAttrToIdMap.put(dnname, dnid);
                        dirAttrFields.add(dnname);
                        dirAttrFieldsHashSet.add(dnname);
                        dirAttrLanguageTexts.add(langstr);
                        dirAttrDnIds.add(dnid);
                        dirAttrExtractorFields.add(dnname + "=");
                        dirAttrIdToExtractorFieldMap.put(dnid, dnname + "=");
                    }
                    ++lines;
                }
                in.close();
                if (log.isDebugEnabled()) {
                    log.debug((Object)("Read profile maps with " + lines + " lines."));
                }
            } else if (log.isDebugEnabled()) {
                log.debug((Object)("Properties file " + propertiesFile + " was not found."));
            }
        }
        catch (IOException e) {
            log.error((Object)"Can not load profile mappings: ", (Throwable)e);
        }
        finally {
            try {
                if (inf != null) {
                    inf.close();
                }
                if (in != null) {
                    in.close();
                }
            }
            catch (IOException e) {
                log.debug((Object)"Error occurred while closing input stream", (Throwable)e);
            }
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private static void loadOrdering() {
        LinkedHashMap<String, ASN1ObjectIdentifier> map = new LinkedHashMap<String, ASN1ObjectIdentifier>();
        BufferedReader in = null;
        InputStreamReader inf = null;
        try {
            InputStream is = obj.getClass().getResourceAsStream("/dncomponents.properties");
            if (is != null) {
                String line;
                inf = new InputStreamReader(is);
                in = new BufferedReader(inf);
                if (!in.ready()) {
                    throw new IOException();
                }
                String[] splits = null;
                while ((line = in.readLine()) != null) {
                    if (line.startsWith("#") || (splits = StringUtils.split((String)line, (char)'=')) == null || splits.length <= 1) continue;
                    String name = splits[0].toLowerCase(Locale.ROOT);
                    ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(splits[1]);
                    map.put(name, oid);
                }
                in.close();
                log.info((Object)"Using DN components from properties file");
                oids.clear();
                oids.putAll(map);
                Set keys = map.keySet();
                dNObjectsForward = keys.toArray(new String[keys.size()]);
            } else {
                log.debug((Object)"Using default values for DN components");
            }
        }
        catch (IOException e) {
            log.debug((Object)"Using default values for DN components");
        }
        finally {
            try {
                if (inf != null) {
                    inf.close();
                }
                if (in != null) {
                    in.close();
                }
            }
            catch (IOException e) {
                log.debug((Object)"Error occurred while closing input stream", (Throwable)e);
            }
        }
    }

    private static List<ASN1ObjectIdentifier> getX509FieldOrder(String[] order) {
        ArrayList<ASN1ObjectIdentifier> fieldOrder = new ArrayList<ASN1ObjectIdentifier>();
        for (String dNObject : order) {
            fieldOrder.add(DnComponents.getOid(dNObject));
        }
        return fieldOrder;
    }

    static {
        oids.put("c", CeSecoreNameStyle.C);
        oids.put("dc", CeSecoreNameStyle.DC);
        oids.put("st", CeSecoreNameStyle.ST);
        oids.put("l", CeSecoreNameStyle.L);
        oids.put("o", CeSecoreNameStyle.O);
        oids.put("ou", CeSecoreNameStyle.OU);
        oids.put("t", CeSecoreNameStyle.T);
        oids.put("surname", CeSecoreNameStyle.SURNAME);
        oids.put("initials", CeSecoreNameStyle.INITIALS);
        oids.put("givenname", CeSecoreNameStyle.GIVENNAME);
        oids.put("gn", CeSecoreNameStyle.GIVENNAME);
        oids.put("sn", CeSecoreNameStyle.SERIALNUMBER);
        oids.put("serialnumber", CeSecoreNameStyle.SERIALNUMBER);
        oids.put("cn", CeSecoreNameStyle.CN);
        oids.put("uid", CeSecoreNameStyle.UID);
        oids.put("dn", CeSecoreNameStyle.DN_QUALIFIER);
        oids.put("emailaddress", CeSecoreNameStyle.EmailAddress);
        oids.put("e", CeSecoreNameStyle.EmailAddress);
        oids.put(EMAIL1, CeSecoreNameStyle.EmailAddress);
        oids.put("unstructuredname", CeSecoreNameStyle.UnstructuredName);
        oids.put("unstructuredaddress", CeSecoreNameStyle.UnstructuredAddress);
        oids.put("postalcode", CeSecoreNameStyle.POSTAL_CODE);
        oids.put("businesscategory", CeSecoreNameStyle.BUSINESS_CATEGORY);
        oids.put("postaladdress", CeSecoreNameStyle.POSTAL_ADDRESS);
        oids.put("telephonenumber", CeSecoreNameStyle.TELEPHONE_NUMBER);
        oids.put("pseudonym", CeSecoreNameStyle.PSEUDONYM);
        oids.put("street", CeSecoreNameStyle.STREET);
        oids.put("name", CeSecoreNameStyle.NAME);
        oids.put("role", CeSecoreNameStyle.ROLE);
        oids.put("description", CeSecoreNameStyle.DESCRIPTION);
        oids.put("jurisdictionlocality", CeSecoreNameStyle.JURISDICTION_LOCALITY);
        oids.put("jurisdictionstate", CeSecoreNameStyle.JURISDICTION_STATE);
        oids.put("jurisdictioncountry", CeSecoreNameStyle.JURISDICTION_COUNTRY);
        oids.put("organizationidentifier", CeSecoreNameStyle.ORGANIZATION_IDENTIFIER);
        oids.put("vid", CeSecoreNameStyle.VID);
        oids.put("pid", CeSecoreNameStyle.PID);
        oids.put("rcacid", CeSecoreNameStyle.RCACID);
        oids.put("icacid", CeSecoreNameStyle.ICACID);
        oids.put("nodeid", CeSecoreNameStyle.NODEID);
        oids.put("fabricid", CeSecoreNameStyle.FABRICID);
        oids.put("noccat", CeSecoreNameStyle.NOCCAT);
        oids.put("fwsigningid", CeSecoreNameStyle.FWSIGNINGID);
        oids.put("uniqueidentifier", CeSecoreNameStyle.UNIQUE_IDENTIFIER);
        oids.put("certificationid", CeSecoreNameStyle.CERTIFICATIONID);
        oids.put("legalentityidentifier", CeSecoreNameStyle.LEGALENTITYIDENTIFIER);
        oids.put("marktype", CeSecoreNameStyle.MARKTYPE);
        oids.put("trademarkcountryorregionname", CeSecoreNameStyle.TRADEMARKCOUNTRYORREGIONNAME);
        oids.put("trademarkofficename", CeSecoreNameStyle.TRADEMARKOFFICENAME);
        oids.put("trademarkidentifier", CeSecoreNameStyle.TRADEMARKIDENTIFIER);
        oids.put("wordmark", CeSecoreNameStyle.WORDMARK);
        oids.put("statutelocalityname", CeSecoreNameStyle.STATUTELOCALITYNAME);
        oids.put("statutestateorprovincename", CeSecoreNameStyle.STATUTESTATEORPROVINCENAME);
        oids.put("statutecountryname", CeSecoreNameStyle.STATUTECOUNTRYNAME);
        oids.put("statutecitation", CeSecoreNameStyle.STATUTECITATION);
        oids.put("statuteurl", CeSecoreNameStyle.STATUTEURL);
        oids.put("priorusemarksourceurl", CeSecoreNameStyle.PRIORUSEMARKSOURCEURL);
        dNObjectsForward = new String[]{"certificationid", "description", "jurisdictioncountry", "jurisdictionstate", "jurisdictionlocality", "role", "street", "pseudonym", "telephonenumber", "postaladdress", "businesscategory", "postalcode", "unstructuredaddress", "unstructuredname", "wordmark", "priorusemarksourceurl", "trademarkidentifier", "legalentityidentifier", "statuteurl", "statutecitation", "trademarkofficename", "statutelocalityname", "statutestateorprovincename", "trademarkcountryorregionname", "statutecountryname", "marktype", "emailaddress", "e", EMAIL1, "dn", "uniqueidentifier", "uid", "pid", "vid", "rcacid", "icacid", "nodeid", "fabricid", "noccat", "fwsigningid", "cn", "name", "sn", "serialnumber", "gn", "givenname", "initials", "surname", "t", "ou", "organizationidentifier", "o", "l", "st", "dc", "c"};
        dNObjectsReverse = null;
        EMAILIDS = new String[]{EMAIL, EMAIL1, EMAIL2, EMAIL3};
        dnNameToIdMap = new HashMap<String, Integer>();
        altNameToIdMap = new HashMap<String, Integer>();
        dirAttrToIdMap = new HashMap<String, Integer>();
        profileNameIdMap = new HashMap<String, Integer>();
        dnIdToProfileNameMap = new HashMap<Integer, String>();
        dnIdToProfileIdMap = new HashMap<Integer, Integer>();
        profileIdToDnIdMap = new HashMap<Integer, Integer>();
        dnErrorTextMap = new HashMap<Integer, String>();
        profileNameLanguageMap = new HashMap<String, String>();
        profileIdLanguageMap = new HashMap<Integer, String>();
        dnIdErrorMap = new HashMap<Integer, String>();
        dnIdToExtractorFieldMap = new HashMap<Integer, String>();
        altNameIdToExtractorFieldMap = new HashMap<Integer, String>();
        dirAttrIdToExtractorFieldMap = new HashMap<Integer, String>();
        dnProfileFields = new ArrayList<String>();
        dnProfileFieldsHashSet = new TreeSet<String>();
        dnLanguageTexts = new ArrayList<String>();
        dnDnIds = new ArrayList<Integer>();
        altNameFields = new ArrayList<String>();
        altNameFieldsHashSet = new TreeSet<String>();
        altNameLanguageTexts = new ArrayList<String>();
        altNameDnIds = new ArrayList<Integer>();
        dirAttrFields = new ArrayList<String>();
        dirAttrFieldsHashSet = new TreeSet<String>();
        dirAttrLanguageTexts = new ArrayList<String>();
        dirAttrDnIds = new ArrayList<Integer>();
        dnExtractorFields = new ArrayList<String>();
        altNameExtractorFields = new ArrayList<String>();
        dirAttrExtractorFields = new ArrayList<String>();
        DnComponents.load();
    }

    private static class X509NameTokenizer {
        private String value;
        private int index;
        private char separator;
        private StringBuffer buf = new StringBuffer();

        public X509NameTokenizer(String oid) {
            this(oid, ',');
        }

        public X509NameTokenizer(String oid, char separator) {
            this.value = oid;
            this.index = -1;
            this.separator = separator;
        }

        public boolean hasMoreTokens() {
            return this.value != null && this.index != this.value.length();
        }

        public String nextToken() {
            int end;
            if (this.index == this.value.length()) {
                return null;
            }
            boolean quoted = false;
            boolean escaped = false;
            this.buf.setLength(0);
            for (end = this.index + 1; end != this.value.length(); ++end) {
                char c = this.value.charAt(end);
                if (c == '\"') {
                    if (!escaped) {
                        quoted = !quoted;
                    } else {
                        if (c == '#' && this.buf.charAt(this.buf.length() - 1) == '=') {
                            this.buf.append('\\');
                        } else if (c == '+' && this.separator != '+') {
                            this.buf.append('\\');
                        }
                        this.buf.append(c);
                    }
                    escaped = false;
                    continue;
                }
                if (escaped || quoted) {
                    if (c == '#' && this.buf.charAt(this.buf.length() - 1) == '=') {
                        this.buf.append('\\');
                    } else if (c == '+' && this.separator != '+') {
                        this.buf.append('\\');
                    }
                    this.buf.append(c);
                    escaped = false;
                    continue;
                }
                if (c == '\\') {
                    escaped = true;
                    continue;
                }
                if (c == this.separator) break;
                this.buf.append(c);
            }
            this.index = end;
            return this.buf.toString().trim();
        }

        String getRemainingString() {
            return this.index + 1 < this.value.length() ? this.value.substring(this.index + 1) : "";
        }
    }

    private static class BasicX509NameTokenizer {
        private final String oid;
        private int index = -1;
        private StringBuilder buf = new StringBuilder();

        public BasicX509NameTokenizer(String oid) {
            this.oid = oid;
        }

        public boolean hasMoreTokens() {
            return this.index != this.oid.length();
        }

        public String nextToken() {
            int end;
            if (this.index == this.oid.length()) {
                return null;
            }
            boolean quoted = false;
            boolean escaped = false;
            this.buf.setLength(0);
            for (end = this.index + 1; end != this.oid.length(); ++end) {
                char c = this.oid.charAt(end);
                if (c == '\"') {
                    if (!escaped) {
                        this.buf.append(c);
                        quoted ^= true;
                    } else {
                        this.buf.append(c);
                    }
                    escaped = false;
                    continue;
                }
                if (escaped || quoted) {
                    this.buf.append(c);
                    escaped = false;
                    continue;
                }
                if (c == '\\') {
                    this.buf.append(c);
                    escaped = true;
                    continue;
                }
                if (c == ',' && !escaped) break;
                this.buf.append(c);
            }
            this.index = end;
            return StringTools.trimUnescaped(this.buf.toString());
        }
    }
}

