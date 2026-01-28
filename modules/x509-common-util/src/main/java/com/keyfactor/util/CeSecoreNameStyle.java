/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.commons.lang.StringUtils
 *  org.bouncycastle.asn1.ASN1Encodable
 *  org.bouncycastle.asn1.ASN1EncodableVector
 *  org.bouncycastle.asn1.ASN1Integer
 *  org.bouncycastle.asn1.ASN1ObjectIdentifier
 *  org.bouncycastle.asn1.ASN1Primitive
 *  org.bouncycastle.asn1.ASN1PrintableString
 *  org.bouncycastle.asn1.ASN1Sequence
 *  org.bouncycastle.asn1.DERPrintableString
 *  org.bouncycastle.asn1.DERSequence
 *  org.bouncycastle.asn1.x500.AttributeTypeAndValue
 *  org.bouncycastle.asn1.x500.RDN
 *  org.bouncycastle.asn1.x500.X500Name
 *  org.bouncycastle.asn1.x500.X500NameStyle
 *  org.bouncycastle.asn1.x500.style.BCStyle
 *  org.bouncycastle.asn1.x500.style.IETFUtils
 */
package com.keyfactor.util;

import java.util.Hashtable;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

public class CeSecoreNameStyle
extends BCStyle {
    public static final X500NameStyle INSTANCE = new CeSecoreNameStyle();
    public static final ASN1ObjectIdentifier JURISDICTION_COUNTRY = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.3");
    public static final ASN1ObjectIdentifier JURISDICTION_STATE = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.2");
    public static final ASN1ObjectIdentifier JURISDICTION_LOCALITY = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.1");
    public static final ASN1ObjectIdentifier DESCRIPTION = new ASN1ObjectIdentifier("2.5.4.13");
    public static final ASN1ObjectIdentifier ROLE = new ASN1ObjectIdentifier("2.5.4.72");
    public static final ASN1ObjectIdentifier VID = new ASN1ObjectIdentifier("1.3.6.1.4.1.37244.2.1");
    public static final ASN1ObjectIdentifier PID = new ASN1ObjectIdentifier("1.3.6.1.4.1.37244.2.2");
    public static final ASN1ObjectIdentifier RCACID = new ASN1ObjectIdentifier("1.3.6.1.4.1.37244.1.4");
    public static final ASN1ObjectIdentifier ICACID = new ASN1ObjectIdentifier("1.3.6.1.4.1.37244.1.3");
    public static final ASN1ObjectIdentifier NODEID = new ASN1ObjectIdentifier("1.3.6.1.4.1.37244.1.1");
    public static final ASN1ObjectIdentifier FABRICID = new ASN1ObjectIdentifier("1.3.6.1.4.1.37244.1.5");
    public static final ASN1ObjectIdentifier NOCCAT = new ASN1ObjectIdentifier("1.3.6.1.4.1.37244.1.6");
    public static final ASN1ObjectIdentifier FWSIGNINGID = new ASN1ObjectIdentifier("1.3.6.1.4.1.37244.1.2");
    public static final ASN1ObjectIdentifier CERTIFICATIONID = new ASN1ObjectIdentifier("0.4.0.127.0.7.3.10.1.2");
    public static final ASN1ObjectIdentifier LEGALENTITYIDENTIFIER = new ASN1ObjectIdentifier("1.3.6.1.4.1.53087.1.5");
    public static final ASN1ObjectIdentifier MARKTYPE = new ASN1ObjectIdentifier("1.3.6.1.4.1.53087.1.13");
    public static final ASN1ObjectIdentifier TRADEMARKCOUNTRYORREGIONNAME = new ASN1ObjectIdentifier("1.3.6.1.4.1.53087.1.3");
    public static final ASN1ObjectIdentifier TRADEMARKOFFICENAME = new ASN1ObjectIdentifier("1.3.6.1.4.1.53087.1.2");
    public static final ASN1ObjectIdentifier TRADEMARKIDENTIFIER = new ASN1ObjectIdentifier("1.3.6.1.4.1.53087.1.4");
    public static final ASN1ObjectIdentifier WORDMARK = new ASN1ObjectIdentifier("1.3.6.1.4.1.53087.1.6");
    public static final ASN1ObjectIdentifier STATUTELOCALITYNAME = new ASN1ObjectIdentifier("1.3.6.1.4.1.53087.3.4");
    public static final ASN1ObjectIdentifier STATUTESTATEORPROVINCENAME = new ASN1ObjectIdentifier("1.3.6.1.4.1.53087.3.3");
    public static final ASN1ObjectIdentifier STATUTECOUNTRYNAME = new ASN1ObjectIdentifier("1.3.6.1.4.1.53087.3.2");
    public static final ASN1ObjectIdentifier STATUTECITATION = new ASN1ObjectIdentifier("1.3.6.1.4.1.53087.3.5");
    public static final ASN1ObjectIdentifier STATUTEURL = new ASN1ObjectIdentifier("1.3.6.1.4.1.53087.3.6");
    public static final ASN1ObjectIdentifier PRIORUSEMARKSOURCEURL = new ASN1ObjectIdentifier("1.3.6.1.4.1.53087.5.1");
    public static final Hashtable<ASN1ObjectIdentifier, String> DefaultSymbols = new Hashtable();
    public static final Hashtable<String, ASN1ObjectIdentifier> DefaultLookUp = new Hashtable();
    public static final Hashtable<String, String> DefaultStringStringLookUp = new Hashtable();

    public static String buildString(Hashtable<ASN1ObjectIdentifier, String> defaultSymbols, X500Name name) {
        StringBuffer buf = new StringBuffer();
        boolean first = true;
        RDN[] rdns = name.getRDNs();
        for (int i = 0; i < rdns.length; ++i) {
            if (first) {
                first = false;
            } else {
                buf.append(',');
            }
            if (rdns[i].isMultiValued()) {
                AttributeTypeAndValue[] atv = rdns[i].getTypesAndValues();
                boolean firstAtv = true;
                for (int j = 0; j != atv.length; ++j) {
                    if (firstAtv) {
                        firstAtv = false;
                    } else {
                        buf.append('+');
                    }
                    CeSecoreNameStyle.appendTypeAndValue(buf, atv[j], defaultSymbols);
                }
                continue;
            }
            CeSecoreNameStyle.appendTypeAndValue(buf, rdns[i].getFirst(), defaultSymbols);
        }
        return buf.toString();
    }

    private static void appendTypeAndValue(StringBuffer buf, AttributeTypeAndValue atv, Hashtable<ASN1ObjectIdentifier, String> defaultSymbols) {
        if (CERTIFICATIONID.equals((ASN1Primitive)atv.getType())) {
            buf.append(defaultSymbols.get(atv.getType()));
            buf.append('=');
            ASN1Sequence seq = ASN1Sequence.getInstance((Object)atv.getValue());
            ASN1PrintableString astr = ASN1PrintableString.getInstance((Object)seq.getObjectAt(1));
            buf.append(astr.toString());
        } else {
            IETFUtils.appendTypeAndValue((StringBuffer)buf, (AttributeTypeAndValue)atv, defaultSymbols);
        }
    }

    public String toString(X500Name name) {
        return CeSecoreNameStyle.buildString(DefaultSymbols, name);
    }

    public ASN1Encodable stringToValue(ASN1ObjectIdentifier oid, String value) {
        if (oid.equals((ASN1Primitive)JURISDICTION_COUNTRY)) {
            return new DERPrintableString(value);
        }
        if (oid.equals((ASN1Primitive)CERTIFICATIONID) && value.length() != 0 && value.charAt(0) != '#') {
            ASN1EncodableVector vec = new ASN1EncodableVector();
            vec.add((ASN1Encodable)new ASN1Integer(1L));
            DERPrintableString str = new DERPrintableString(value);
            if (str.getString().length() != 18) {
                throw new IllegalArgumentException("BSI CertificationID must be exactly 18 characters in length. " + value + " is " + str.getString().length());
            }
            vec.add((ASN1Encodable)str);
            return new DERSequence(vec);
        }
        return super.stringToValue(oid, value);
    }

    public ASN1ObjectIdentifier attrNameToOID(String attrName) {
        String attr = attrName;
        if (StringUtils.equals((String)attrName, (String)"EMAIL") || StringUtils.equals((String)attrName, (String)"EMAILADDRESS")) {
            attr = "E";
        }
        return IETFUtils.decodeAttrName((String)attr, DefaultLookUp);
    }

    static {
        DefaultSymbols.put(C, "C");
        DefaultSymbols.put(O, "O");
        DefaultSymbols.put(T, "T");
        DefaultSymbols.put(OU, "OU");
        DefaultSymbols.put(CN, "CN");
        DefaultSymbols.put(L, "L");
        DefaultSymbols.put(ST, "ST");
        DefaultSymbols.put(SERIALNUMBER, "SN");
        DefaultSymbols.put(EmailAddress, "E");
        DefaultSymbols.put(DC, "DC");
        DefaultSymbols.put(UID, "UID");
        DefaultSymbols.put(STREET, "STREET");
        DefaultSymbols.put(SURNAME, "SURNAME");
        DefaultSymbols.put(GIVENNAME, "GIVENNAME");
        DefaultSymbols.put(INITIALS, "INITIALS");
        DefaultSymbols.put(GENERATION, "GENERATION");
        DefaultSymbols.put(UnstructuredAddress, "unstructuredAddress");
        DefaultSymbols.put(UnstructuredName, "unstructuredName");
        DefaultSymbols.put(UNIQUE_IDENTIFIER, "UniqueIdentifier");
        DefaultSymbols.put(DN_QUALIFIER, "DN");
        DefaultSymbols.put(PSEUDONYM, "Pseudonym");
        DefaultSymbols.put(POSTAL_ADDRESS, "PostalAddress");
        DefaultSymbols.put(NAME_AT_BIRTH, "NameAtBirth");
        DefaultSymbols.put(COUNTRY_OF_CITIZENSHIP, "CountryOfCitizenship");
        DefaultSymbols.put(COUNTRY_OF_RESIDENCE, "CountryOfResidence");
        DefaultSymbols.put(GENDER, "Gender");
        DefaultSymbols.put(PLACE_OF_BIRTH, "PlaceOfBirth");
        DefaultSymbols.put(DATE_OF_BIRTH, "DateOfBirth");
        DefaultSymbols.put(POSTAL_CODE, "PostalCode");
        DefaultSymbols.put(BUSINESS_CATEGORY, "BusinessCategory");
        DefaultSymbols.put(TELEPHONE_NUMBER, "TelephoneNumber");
        DefaultSymbols.put(NAME, "Name");
        DefaultSymbols.put(ROLE, "Role");
        DefaultSymbols.put(JURISDICTION_LOCALITY, "JurisdictionLocality");
        DefaultSymbols.put(JURISDICTION_STATE, "JurisdictionState");
        DefaultSymbols.put(JURISDICTION_COUNTRY, "JurisdictionCountry");
        DefaultSymbols.put(ORGANIZATION_IDENTIFIER, "organizationIdentifier");
        DefaultSymbols.put(DESCRIPTION, "description");
        DefaultSymbols.put(VID, "VID");
        DefaultSymbols.put(PID, "PID");
        DefaultSymbols.put(RCACID, "RCACID");
        DefaultSymbols.put(ICACID, "ICACID");
        DefaultSymbols.put(NODEID, "NODEID");
        DefaultSymbols.put(FABRICID, "FABRICID");
        DefaultSymbols.put(NOCCAT, "NOCCAT");
        DefaultSymbols.put(FWSIGNINGID, "FWSIGNINGID");
        DefaultSymbols.put(CERTIFICATIONID, "CertificationID");
        DefaultSymbols.put(LEGALENTITYIDENTIFIER, "legalEntityIdentifier");
        DefaultSymbols.put(MARKTYPE, "markType");
        DefaultSymbols.put(TRADEMARKCOUNTRYORREGIONNAME, "trademarkCountryOrRegionName");
        DefaultSymbols.put(TRADEMARKOFFICENAME, "trademarkOfficeName");
        DefaultSymbols.put(TRADEMARKIDENTIFIER, "trademarkIdentifier");
        DefaultSymbols.put(WORDMARK, "wordMark");
        DefaultSymbols.put(STATUTELOCALITYNAME, "statuteLocalityName");
        DefaultSymbols.put(STATUTESTATEORPROVINCENAME, "statuteStateOrProvinceName");
        DefaultSymbols.put(STATUTECOUNTRYNAME, "statuteCountryName");
        DefaultSymbols.put(STATUTECITATION, "statuteCitation");
        DefaultSymbols.put(STATUTEURL, "statuteURL");
        DefaultSymbols.put(PRIORUSEMARKSOURCEURL, "priorUseMarkSourceURL");
        DefaultLookUp.put("c", C);
        DefaultLookUp.put("o", O);
        DefaultLookUp.put("t", T);
        DefaultLookUp.put("ou", OU);
        DefaultLookUp.put("cn", CN);
        DefaultLookUp.put("l", L);
        DefaultLookUp.put("st", ST);
        DefaultLookUp.put("sn", SERIALNUMBER);
        DefaultLookUp.put("serialnumber", SERIALNUMBER);
        DefaultLookUp.put("street", STREET);
        DefaultLookUp.put("emailaddress", E);
        DefaultLookUp.put("dc", DC);
        DefaultLookUp.put("e", E);
        DefaultLookUp.put("uid", UID);
        DefaultLookUp.put("surname", SURNAME);
        DefaultLookUp.put("givenname", GIVENNAME);
        DefaultLookUp.put("initials", INITIALS);
        DefaultLookUp.put("generation", GENERATION);
        DefaultLookUp.put("unstructuredaddress", UnstructuredAddress);
        DefaultLookUp.put("unstructuredname", UnstructuredName);
        DefaultLookUp.put("uniqueidentifier", UNIQUE_IDENTIFIER);
        DefaultLookUp.put("dn", DN_QUALIFIER);
        DefaultLookUp.put("pseudonym", PSEUDONYM);
        DefaultLookUp.put("postaladdress", POSTAL_ADDRESS);
        DefaultLookUp.put("nameofbirth", NAME_AT_BIRTH);
        DefaultLookUp.put("countryofcitizenship", COUNTRY_OF_CITIZENSHIP);
        DefaultLookUp.put("countryofresidence", COUNTRY_OF_RESIDENCE);
        DefaultLookUp.put("gender", GENDER);
        DefaultLookUp.put("placeofbirth", PLACE_OF_BIRTH);
        DefaultLookUp.put("dateofbirth", DATE_OF_BIRTH);
        DefaultLookUp.put("postalcode", POSTAL_CODE);
        DefaultLookUp.put("businesscategory", BUSINESS_CATEGORY);
        DefaultLookUp.put("telephonenumber", TELEPHONE_NUMBER);
        DefaultLookUp.put("name", NAME);
        DefaultLookUp.put("role", ROLE);
        DefaultLookUp.put("jurisdictionlocality", JURISDICTION_LOCALITY);
        DefaultLookUp.put("jurisdictionstate", JURISDICTION_STATE);
        DefaultLookUp.put("jurisdictioncountry", JURISDICTION_COUNTRY);
        DefaultLookUp.put("organizationidentifier", ORGANIZATION_IDENTIFIER);
        DefaultLookUp.put("description", DESCRIPTION);
        DefaultLookUp.put("vid", VID);
        DefaultLookUp.put("pid", PID);
        DefaultLookUp.put("rcacid", RCACID);
        DefaultLookUp.put("icacid", ICACID);
        DefaultLookUp.put("nodeid", NODEID);
        DefaultLookUp.put("fabricid", FABRICID);
        DefaultLookUp.put("noccat", NOCCAT);
        DefaultLookUp.put("fwsigningid", FWSIGNINGID);
        DefaultLookUp.put("certificationid", CERTIFICATIONID);
        DefaultLookUp.put("legalentityidentifier", LEGALENTITYIDENTIFIER);
        DefaultLookUp.put("marktype", MARKTYPE);
        DefaultLookUp.put("trademarkcountryorregionname", TRADEMARKCOUNTRYORREGIONNAME);
        DefaultLookUp.put("trademarkofficename", TRADEMARKOFFICENAME);
        DefaultLookUp.put("trademarkidentifier", TRADEMARKIDENTIFIER);
        DefaultLookUp.put("wordmark", WORDMARK);
        DefaultLookUp.put("statutelocalityname", STATUTELOCALITYNAME);
        DefaultLookUp.put("statutestateorprovincename", STATUTESTATEORPROVINCENAME);
        DefaultLookUp.put("statutecountryname", STATUTECOUNTRYNAME);
        DefaultLookUp.put("statutecitation", STATUTECITATION);
        DefaultLookUp.put("statuteurl", STATUTEURL);
        DefaultLookUp.put("priorusemarksourceurl", PRIORUSEMARKSOURCEURL);
        DefaultStringStringLookUp.put("C", C.getId());
        DefaultStringStringLookUp.put("O", O.getId());
        DefaultStringStringLookUp.put("T", T.getId());
        DefaultStringStringLookUp.put("OU", OU.getId());
        DefaultStringStringLookUp.put("CN", CN.getId());
        DefaultStringStringLookUp.put("L", L.getId());
        DefaultStringStringLookUp.put("ST", ST.getId());
        DefaultStringStringLookUp.put("SN", SERIALNUMBER.getId());
        DefaultStringStringLookUp.put("SERIALNUMBER", SERIALNUMBER.getId());
        DefaultStringStringLookUp.put("STREET", STREET.getId());
        DefaultStringStringLookUp.put("EMAILADDRESS", E.getId());
        DefaultStringStringLookUp.put("DC", DC.getId());
        DefaultStringStringLookUp.put("E", E.getId());
        DefaultStringStringLookUp.put("UID", UID.getId());
        DefaultStringStringLookUp.put("SURNAME", SURNAME.getId());
        DefaultStringStringLookUp.put("GIVENNAME", GIVENNAME.getId());
        DefaultStringStringLookUp.put("INITIALS", INITIALS.getId());
        DefaultStringStringLookUp.put("GENERATION", GENERATION.getId());
        DefaultStringStringLookUp.put("UNSTRUCTUREDADDRESS", UnstructuredAddress.getId());
        DefaultStringStringLookUp.put("UNSTRUCTUREDNAME", UnstructuredName.getId());
        DefaultStringStringLookUp.put("UNIQUEIDENTIFIER", UNIQUE_IDENTIFIER.getId());
        DefaultStringStringLookUp.put("DN", DN_QUALIFIER.getId());
        DefaultStringStringLookUp.put("PSEUDONYM", PSEUDONYM.getId());
        DefaultStringStringLookUp.put("POSTALADDRESS", POSTAL_ADDRESS.getId());
        DefaultStringStringLookUp.put("NAMEOFBIRTH", NAME_AT_BIRTH.getId());
        DefaultStringStringLookUp.put("COUNTRYOFCITIZENSHIP", COUNTRY_OF_CITIZENSHIP.getId());
        DefaultStringStringLookUp.put("COUNTRYOFRESIDENCE", COUNTRY_OF_RESIDENCE.getId());
        DefaultStringStringLookUp.put("GENDER", GENDER.getId());
        DefaultStringStringLookUp.put("PLACEOFBIRTH", PLACE_OF_BIRTH.getId());
        DefaultStringStringLookUp.put("DATEOFBIRTH", DATE_OF_BIRTH.getId());
        DefaultStringStringLookUp.put("POSTALCODE", POSTAL_CODE.getId());
        DefaultStringStringLookUp.put("BUSINESSCATEGORY", BUSINESS_CATEGORY.getId());
        DefaultStringStringLookUp.put("TELEPHONENUMBER", TELEPHONE_NUMBER.getId());
        DefaultStringStringLookUp.put("NAME", NAME.getId());
        DefaultStringStringLookUp.put("ROLE", ROLE.getId());
        DefaultStringStringLookUp.put("JURISDICTIONLOCALITY", JURISDICTION_LOCALITY.getId());
        DefaultStringStringLookUp.put("JURISDICTIONSTATE", JURISDICTION_STATE.getId());
        DefaultStringStringLookUp.put("JURISDICTIONCOUNTRY", JURISDICTION_COUNTRY.getId());
        DefaultStringStringLookUp.put("ORGANIZATIONIDENTIFIER", ORGANIZATION_IDENTIFIER.getId());
        DefaultStringStringLookUp.put("DESCRIPTION", DESCRIPTION.getId());
        DefaultStringStringLookUp.put("VID", VID.getId());
        DefaultStringStringLookUp.put("PID", PID.getId());
        DefaultStringStringLookUp.put("PID", PID.getId());
        DefaultStringStringLookUp.put("RCACID", RCACID.getId());
        DefaultStringStringLookUp.put("ICAIID", ICACID.getId());
        DefaultStringStringLookUp.put("NODEID", NODEID.getId());
        DefaultStringStringLookUp.put("FABRICID", FABRICID.getId());
        DefaultStringStringLookUp.put("NOCCAT", NOCCAT.getId());
        DefaultStringStringLookUp.put("FWSIGNINGID", FWSIGNINGID.getId());
        DefaultStringStringLookUp.put("CERTIFICATIONID", CERTIFICATIONID.getId());
        DefaultStringStringLookUp.put("LEGALENTITYIDENTIFIER", LEGALENTITYIDENTIFIER.getId());
        DefaultStringStringLookUp.put("MARKTYPE", MARKTYPE.getId());
        DefaultStringStringLookUp.put("TRADEMARKCOUNTRYORREGIONNAME", TRADEMARKCOUNTRYORREGIONNAME.getId());
        DefaultStringStringLookUp.put("TRADEMARKOFFICENAME", TRADEMARKOFFICENAME.getId());
        DefaultStringStringLookUp.put("TRADEMARKIDENTIFIER", TRADEMARKIDENTIFIER.getId());
        DefaultStringStringLookUp.put("WORDMARK", WORDMARK.getId());
        DefaultStringStringLookUp.put("STATUTELOCALITYNAME", STATUTELOCALITYNAME.getId());
        DefaultStringStringLookUp.put("STATUTESTATEORPROVINCENAME", STATUTESTATEORPROVINCENAME.getId());
        DefaultStringStringLookUp.put("STATUTECOUNTRYNAME", STATUTECOUNTRYNAME.getId());
        DefaultStringStringLookUp.put("STATUTECITATION", STATUTECITATION.getId());
        DefaultStringStringLookUp.put("STATUTEURL", STATUTEURL.getId());
        DefaultStringStringLookUp.put("PRIORUSEMARKSOURCEURL", PRIORUSEMARKSOURCEURL.getId());
    }
}

