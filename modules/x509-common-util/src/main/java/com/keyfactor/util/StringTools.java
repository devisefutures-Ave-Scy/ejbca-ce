/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  com.google.common.net.InternetDomainName
 *  org.apache.commons.lang.CharUtils
 *  org.apache.commons.lang.StringUtils
 *  org.apache.log4j.Logger
 *  org.bouncycastle.util.encoders.DecoderException
 *  org.bouncycastle.util.encoders.Hex
 */
package com.keyfactor.util;

import com.google.common.net.InternetDomainName;
import com.keyfactor.util.Base64;
import com.keyfactor.util.RandomHelper;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.string.StringConfigurationCache;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.apache.commons.lang.CharUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;

public final class StringTools {
    private static final Logger log = Logger.getLogger(StringTools.class);
    private static Pattern VALID_IPV4_PATTERN = null;
    private static Pattern VALID_IPV6_PATTERN = null;
    private static Pattern windowsOrMacNewlines = Pattern.compile("\r\n?");
    private static final String ipv4Pattern = "(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])";
    private static final String ipv6Pattern = "^([\\dA-F]{1,4}:|((?=.*(::))(?!.*\\3.+\\3))\\3?)([\\dA-F]{1,4}(\\3|:\\b)|\\2){5}(([\\dA-F]{1,4}(\\3|:\\b|$)|\\2){2}|(((2[0-4]|1\\d|[1-9])?\\d|25[0-5])\\.?\\b){4})\\z";
    private static Pattern VALID_RFC5322_USER_PART = null;
    private static Pattern VALID_RFC5322_EMAIL = null;
    private static final String emailUserPart = "^[a-z0-9]+[a-z0-9_!#$%&'*+/=?`{|}~^.-]+";
    private static final String email = "^[a-z0-9]+[a-z0-9_!#$%&'*+/=?`{|}~^.-]+@[a-z0-9]+[a-z0-9.-]+[a-z0-9]+$";
    private static final CharSet STRIP_XSS;
    private static final CharSet STRIP_SQL_CHARS;
    private static final CharSet STRIP_SDATT_STRIP_CHARS;
    private static final CharSet STRIP_SQL_CHARS_SINGLE_QUOTE_ESCAPED;
    private static final CharSet STRIP_FILENAME_CHARS;
    private static final CharSet ALLOWED_ESCAPE_CHARS;
    private static final Pattern WS;
    private static final Pattern SPACE_AND_COLON;
    public static final int KEY_SEQUENCE_FORMAT_NUMERIC = 1;
    public static final int KEY_SEQUENCE_FORMAT_ALPHANUMERIC = 2;
    public static final int KEY_SEQUENCE_FORMAT_COUNTRY_CODE_PLUS_NUMERIC = 4;
    public static final int KEY_SEQUENCE_FORMAT_COUNTRY_CODE_PLUS_ALPHANUMERIC = 8;

    private StringTools() {
    }

    public static List<String> toLowerCase(List<String> strings) {
        ArrayList<String> lowerCaseStrings = new ArrayList<String>();
        for (String string : strings) {
            lowerCaseStrings.add(string.toLowerCase());
        }
        return lowerCaseStrings;
    }

    public static String strip(String str) {
        return StringTools.strip(str, CharSet.INSTANCE);
    }

    public static String stripUsername(String str) {
        String xssStripped = StringTools.strip(str, STRIP_XSS);
        return StringTools.strip(StringTools.trim(xssStripped));
    }

    public static String stripFilename(String str) {
        return StringTools.stripWithEscapesDisallowed(str, STRIP_FILENAME_CHARS);
    }

    public static String stripFilenameReplaceSpaces(String str) {
        return StringTools.stripFilename(str.replace(" ", "_esc_spc_"));
    }

    private static String stripWithEscapesDisallowed(String str, CharSet stripThis) {
        if (str == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < str.length(); ++i) {
            if (stripThis.contains(str.charAt(i))) continue;
            sb.append(str.charAt(i));
        }
        return sb.toString();
    }

    public static String stripLog(String str) {
        if (str == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < str.length(); ++i) {
            if (str.charAt(i) < ' ') continue;
            sb.append(str.charAt(i));
        }
        return sb.toString();
    }

    private static String strip(String str, CharSet stripThis) {
        if (str == null) {
            return null;
        }
        StringBuilder buf = new StringBuilder(str);
        int end = buf.length();
        for (int index = 0; index < end; ++index) {
            if (buf.charAt(index) == '\\') {
                if (index + 1 == end) {
                    buf.setCharAt(index, '/');
                    continue;
                }
                if (!StringTools.isAllowedEscape(buf.charAt(index + 1))) {
                    buf.setCharAt(index, '/');
                    buf.deleteCharAt(index + 1);
                    --end;
                    continue;
                }
                ++index;
                continue;
            }
            if (!stripThis.contains(buf.charAt(index))) continue;
            buf.setCharAt(index, '/');
        }
        String result = buf.toString();
        if (log.isTraceEnabled() && !result.equals(str)) {
            log.trace((Object)("Some chars stripped. Was '" + str + "' is now '" + result + "'."));
        }
        return result;
    }

    public static Set<String> hasSqlStripChars(String str) {
        return StringTools.hasStripChars(str, STRIP_SQL_CHARS);
    }

    public static Set<String> hasSDAttrStripChars(String str) {
        return StringTools.hasStripChars(str, STRIP_SDATT_STRIP_CHARS);
    }

    public static Set<String> hasSqlStripCharsAssumingSingleQuoteEscape(String str) {
        return StringTools.hasStripChars(str, STRIP_SQL_CHARS_SINGLE_QUOTE_ESCAPED);
    }

    public static Set<String> hasStripChars(String str) {
        return StringTools.hasStripChars(str, CharSet.INSTANCE);
    }

    private static Set<String> hasStripChars(String str, CharSet checkThese) {
        HashSet<String> result = new HashSet<String>();
        if (str == null) {
            return result;
        }
        int end = str.length();
        for (int index = 0; index < end; ++index) {
            if (str.charAt(index) == '\\') {
                if (index + 1 == end) {
                    result.add("A trailing escape charater ('').");
                    break;
                }
                if (!StringTools.isAllowedEscape(str.charAt(index + 1))) {
                    result.add("Character that may not be escaped: " + str.charAt(index + 1));
                    break;
                }
                ++index;
                continue;
            }
            if (!checkThese.contains(str.charAt(index))) continue;
            result.add("'" + str.charAt(index) + "'");
        }
        return result;
    }

    private static boolean isAllowedEscape(char ch) {
        return ALLOWED_ESCAPE_CHARS.contains(ch) && !CharSet.INSTANCE.contains(ch);
    }

    public static String stripWhitespace(String str) {
        if (str == null) {
            return null;
        }
        return WS.matcher(str).replaceAll("");
    }

    public static String removeAllWhitespaceAndColon(String str) {
        if (str == null) {
            return null;
        }
        return SPACE_AND_COLON.matcher(StringUtils.removeStart((String)str, (String)"0x")).replaceAll("");
    }

    public static String ipOctetsToString(byte[] octets) {
        String ret;
        block7: {
            ret = null;
            if (octets.length == 4) {
                StringBuilder ip = new StringBuilder("");
                for (int i = 0; i < 4; ++i) {
                    int intByte = 0xFF & octets[i];
                    short t = (short)intByte;
                    if (StringUtils.isNotEmpty((String)ip.toString())) {
                        ip.append(".");
                    }
                    ip.append(t);
                }
                ret = ip.toString();
            } else if (octets.length == 16) {
                try {
                    ret = InetAddress.getByAddress(octets).getHostAddress();
                }
                catch (UnknownHostException e) {
                    if (!log.isDebugEnabled()) break block7;
                    log.debug((Object)("Invalid IP address parsing octets: " + Hex.toHexString((byte[])octets)));
                }
            }
        }
        return ret;
    }

    public static String convertToIpv6(String address) {
        String ret = "";
        if (address.startsWith("#")) {
            ret = address.replaceFirst("#", "");
        }
        StringBuilder ipV6 = new StringBuilder("");
        for (int i = 0; i < ret.length(); ++i) {
            ipV6.append(ret.charAt(i));
            if ((i + 1) % 4 != 0 || i + 1 == ret.length()) continue;
            ipV6.append(":");
        }
        return ipV6.toString();
    }

    public static byte[] ipStringToOctets(String str) {
        byte[] ret = null;
        if (StringTools.isIpAddress(str)) {
            try {
                InetAddress adr = InetAddress.getByName(str);
                ret = adr.getAddress();
            }
            catch (UnknownHostException e) {
                log.info((Object)"Error parsing ip address (ipv4 or ipv6): ", (Throwable)e);
            }
        }
        if (ret == null) {
            log.info((Object)"Not a IPv4 or IPv6 address, returning empty array.");
            ret = new byte[]{};
        }
        return ret;
    }

    public static boolean isIpAddress(String ipAddress) {
        Matcher m1 = VALID_IPV4_PATTERN.matcher(ipAddress);
        if (m1.matches()) {
            return true;
        }
        Matcher m2 = VALID_IPV6_PATTERN.matcher(ipAddress);
        return m2.matches();
    }

    public static boolean isIpV4Address(String ipAddress) {
        return VALID_IPV4_PATTERN.matcher(ipAddress).matches();
    }

    public static boolean isIpV6Address(String ipAddress) {
        return VALID_IPV6_PATTERN.matcher(ipAddress).matches();
    }

    public static boolean isValidEmailUserPart(String emailUserPart) {
        return VALID_RFC5322_USER_PART.matcher(emailUserPart).matches();
    }

    public static boolean isValidEmail(String email) {
        return VALID_RFC5322_EMAIL.matcher(email).matches();
    }

    public static boolean isValidUri(String uri) {
        try {
            new URL(uri).toURI();
        }
        catch (MalformedURLException | URISyntaxException e) {
            return false;
        }
        return true;
    }

    public static boolean isValidSanDnsName(String dnsName) {
        if (dnsName == null) {
            return false;
        }
        if (dnsName.endsWith(".")) {
            return false;
        }
        dnsName = dnsName.startsWith("*.") ? dnsName.substring(2) : dnsName;
        return InternetDomainName.isValid((String)dnsName);
    }

    public static String putBase64String(String s) {
        return StringTools.putBase64String(s, false);
    }

    public static String putBase64String(String s, boolean dontEncodeAsciiPrintable) {
        if (StringUtils.isEmpty((String)s)) {
            return s;
        }
        if (s.startsWith("B64:")) {
            return s;
        }
        if (dontEncodeAsciiPrintable && StringUtils.isAsciiPrintable((String)s)) {
            return s;
        }
        return "B64:" + new String(Base64.encode(s.getBytes(StandardCharsets.UTF_8), false));
    }

    public static String getBase64String(String input) {
        if (StringUtils.isEmpty((String)input)) {
            return input;
        }
        if (!input.toLowerCase().startsWith("b64:")) {
            return input;
        }
        String base64Data = input.substring(4);
        if (base64Data.length() == 0) {
            return input;
        }
        try {
            return new String(Base64.decode(base64Data.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
        }
        catch (DecoderException e) {
            return input;
        }
    }

    public static BigInteger getBigIntegerFromHexString(String hexString) {
        if (hexString.startsWith("0x") || hexString.startsWith("0X")) {
            hexString = hexString.substring(2, hexString.length());
        }
        return new BigInteger(hexString, 16);
    }

    public static String obfuscateIfNot(String s) {
        if (s.startsWith("OBF:")) {
            return s;
        }
        return StringTools.obfuscate(s);
    }

    public static String obfuscate(String s) {
        if (StringUtils.isEmpty((String)s)) {
            return s;
        }
        StringBuilder buf = new StringBuilder(32);
        buf.append("OBF:");
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < b.length; ++i) {
            int b1 = b[i] & 0xFF;
            int b2 = b[b.length - (i + 1)] & 0x7F | b1 & 0x80;
            int i1 = b1 + b2 + 127;
            int i2 = b1 - b2 + 127;
            int i0 = i1 * 256 + i2;
            if (i0 < 0) {
                throw new IllegalStateException("Negative number " + i0);
            }
            String x = Integer.toString(i0, 36);
            if (x.length() > 4) {
                throw new IllegalStateException("Too long integer " + x);
            }
            for (int j = 0; j < 4 - x.length(); ++j) {
                buf.append('0');
            }
            buf.append(x);
        }
        return buf.toString();
    }

    public static String deobfuscateIf(String s) {
        if (s != null && s.startsWith("OBF:")) {
            return StringTools.deobfuscate(s);
        }
        return s;
    }

    public static String deobfuscate(String in) {
        String s = in;
        if (s != null && s.startsWith("OBF:")) {
            s = s.substring(4);
        }
        if (StringUtils.isEmpty((String)s)) {
            return s;
        }
        byte[] b = new byte[s.length() / 2];
        int l = 0;
        for (int i = 0; i < s.length(); i += 4) {
            String x = s.substring(i, i + 4);
            int i0 = Integer.parseInt(x, 36);
            int i1 = i0 / 256;
            int i2 = i0 % 256;
            b[l++] = (byte)((i1 + i2 - 254) / 2);
        }
        return new String(b, 0, l, StandardCharsets.UTF_8);
    }

    private static String getEncryptionVersion() {
        return "encv1";
    }

    /*
     * Enabled force condition propagation
     * Lifted jumps to return sites
     */
    public static String getEncryptVersionFromString(String in) {
        if (in != null && in.contains(":")) {
            String[] strs = StringUtils.split((String)in, (char)':');
            if (strs != null && strs.length == 4) return strs[0];
            log.warn((Object)"Password/PIN is not encrypted: does not match the expected EJBCA encryption format (with 4 fields). It will be processed as plain text.");
            return "legacy";
        }
        try {
            Hex.decode((String)in);
            return "legacy";
        }
        catch (DecoderException e) {
            return "none";
        }
    }

    private static byte[] getSalt(boolean useLegacySalt) {
        if (useLegacySalt) {
            log.debug((Object)"Using legacy password encryption/decryption");
            return StringTools.getDefaultSalt();
        }
        SecureRandom random = RandomHelper.getInstance("BCSP800HYBRID");
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return bytes;
    }

    private static byte[] getDefaultSalt() {
        return "1958473059684739584hfurmaqiekcmq".getBytes(StandardCharsets.UTF_8);
    }

    private static int getDefaultCount() {
        return 100;
    }

    private static int getCount(boolean legacyCount) {
        if (!legacyCount) {
            return StringConfigurationCache.INSTANCE.getPasswordEncryptionCount();
        }
        return 100;
    }

    public static String pbeEncryptStringWithSha256Aes192(String in, String encryptionKey, boolean legacyMode) {
        return StringTools.pbeEncryptStringWithSha256Aes192(in, encryptionKey.toCharArray(), legacyMode);
    }

    public static String pbeEncryptStringWithSha256Aes192(String in, char[] p, boolean legacyMode) {
        byte[] enc;
        if (in == null) {
            return in;
        }
        if (KeyTools.isUsingExportableCryptography()) {
            log.warn((Object)"Encryption not possible due to weak crypto policy.");
            return in;
        }
        byte[] salt = StringTools.getSalt(legacyMode);
        int count = StringTools.getCount(legacyMode);
        PBEKeySpec keySpec = new PBEKeySpec(p, salt, count);
        String algorithm = "PBEWithSHA256And192BitAES-CBC-BC";
        try {
            Cipher c = Cipher.getInstance("PBEWithSHA256And192BitAES-CBC-BC", "BC");
            SecretKeyFactory fact = SecretKeyFactory.getInstance("PBEWithSHA256And192BitAES-CBC-BC", "BC");
            c.init(1, fact.generateSecret(keySpec));
            enc = c.doFinal(in.getBytes(StandardCharsets.UTF_8));
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Hard coded algorithm PBEWithSHA256And192BitAES-CBC-BC was not found.", e);
        }
        catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle provider was not installed.", e);
        }
        catch (NoSuchPaddingException e) {
            throw new IllegalStateException("Padding for hard coded algorithm PBEWithSHA256And192BitAES-CBC-BC was not found.", e);
        }
        catch (GeneralSecurityException e) {
            throw new IllegalStateException("Password-Based Encryption (PBE) failed.", e);
        }
        StringBuilder ret = new StringBuilder(64);
        if (legacyMode) {
            ret.append(Hex.toHexString((byte[])enc));
        } else {
            ret.append(StringTools.getEncryptionVersion()).append(':').append(Hex.toHexString((byte[])salt)).append(':').append(count).append(':').append(Hex.toHexString((byte[])enc));
        }
        if (log.isTraceEnabled()) {
            log.trace((Object)("Encrypted data: " + ret.toString()));
        }
        return ret.toString();
    }

    public static String pbeDecryptStringWithSha256Aes192(String in) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        char[] p = StringConfigurationCache.INSTANCE.getEncryptionKey();
        return StringTools.pbeDecryptStringWithSha256Aes192(in, p);
    }

    public static String pbeDecryptStringWithSha256Aes192(String in, char[] p) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
        int count;
        byte[] salt;
        if (KeyTools.isUsingExportableCryptography()) {
            log.warn((Object)"Decryption not possible due to weak crypto policy.");
            return in;
        }
        String data = in;
        if (in != null && in.contains(":")) {
            String[] strs = StringUtils.split((String)in, (char)':');
            if (strs == null || strs.length != 4) {
                log.warn((Object)"Password/PIN is not encrypted: does not match the expected EJBCA encryption format (with 4 fields). It will be processed as plain text.");
                return in;
            }
            salt = Hex.decode((byte[])strs[1].getBytes(StandardCharsets.UTF_8));
            count = Integer.parseInt(strs[2]);
            data = strs[3];
        } else {
            salt = StringTools.getDefaultSalt();
            count = StringTools.getDefaultCount();
        }
        String algorithm = "PBEWithSHA256And192BitAES-CBC-BC";
        try {
            Cipher c = Cipher.getInstance("PBEWithSHA256And192BitAES-CBC-BC", "BC");
            PBEKeySpec keySpec = new PBEKeySpec(p, salt, count);
            SecretKeyFactory fact = SecretKeyFactory.getInstance("PBEWithSHA256And192BitAES-CBC-BC", "BC");
            c.init(2, fact.generateSecret(keySpec));
            byte[] dec = c.doFinal(Hex.decode((byte[])data.getBytes(StandardCharsets.UTF_8)));
            return new String(dec);
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Hard coded algorithm PBEWithSHA256And192BitAES-CBC-BC was not found.", e);
        }
        catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle provider was not installed.", e);
        }
        catch (NoSuchPaddingException e) {
            throw new IllegalStateException("Padding for hard coded algorithm PBEWithSHA256And192BitAES-CBC-BC was not found.", e);
        }
    }

    public static String passwordDecryption(String in, String sDebug) {
        if (in == null) {
            return null;
        }
        try {
            String tmp = StringTools.pbeDecryptStringWithSha256Aes192(in, StringConfigurationCache.INSTANCE.getEncryptionKey());
            if (log.isDebugEnabled()) {
                log.debug((Object)("Using encrypted " + sDebug));
            }
            return tmp;
        }
        catch (Throwable t) {
            try {
                String tmp = StringTools.pbeDecryptStringWithSha256Aes192(in, StringConfigurationCache.INSTANCE.getEncryptionKey());
                log.warn((Object)("Using encrypted " + sDebug + " (falling back to default 'password.encryption.key')"));
                return tmp;
            }
            catch (Throwable t2) {
                if (in.matches("[0-9a-fA-F]+") && in.length() % 32 == 0) {
                    log.error((Object)"Password decryption failed. 'password.encryption.key' might have been modified more than once.");
                }
                if (log.isDebugEnabled()) {
                    log.debug((Object)("Using cleartext " + sDebug));
                }
                return in;
            }
        }
    }

    public static String incrementKeySequence(int keySequenceFormat, String oldSequence) {
        if (log.isTraceEnabled()) {
            log.trace((Object)(">incrementKeySequence: " + keySequenceFormat + ", " + oldSequence));
        }
        String ret = null;
        if (keySequenceFormat == 1) {
            ret = StringTools.incrementNumeric(oldSequence);
        } else if (keySequenceFormat == 2) {
            ret = StringTools.incrementAlphaNumeric(oldSequence);
        } else if (keySequenceFormat == 4) {
            final String countryCode = oldSequence.substring(0, Math.min(2, oldSequence.length()));
            if (log.isDebugEnabled()) {
                log.debug((Object)("countryCode: " + countryCode));
            }
            final String inc = StringTools.incrementNumeric(oldSequence.substring(2));
            if (oldSequence.length() > 2 && inc != null) {
                ret = countryCode + inc;
            }
        } else if (keySequenceFormat == 8) {
            final String countryCode = oldSequence.substring(0, Math.min(2, oldSequence.length()));
            if (log.isDebugEnabled()) {
                log.debug((Object)("countryCode: " + countryCode));
            }
            final String inc = StringTools.incrementAlphaNumeric(oldSequence.substring(2));
            if (oldSequence.length() > 2 && inc != null) {
                ret = countryCode + inc;
            }
        }
        if (ret == null) {
            char c;
            ret = oldSequence;
            StringBuilder buf = new StringBuilder();
            for (int i = oldSequence.length() - 1; i >= 0 && CharUtils.isAsciiNumeric((char)(c = oldSequence.charAt(i))); --i) {
                buf.insert(0, c);
            }
            int restlen = oldSequence.length() - buf.length();
            String rest = oldSequence.substring(0, restlen);
            String intStr = buf.toString();
            if (StringUtils.isNotEmpty((String)intStr)) {
                Integer seq = Integer.valueOf(intStr);
                seq = seq + 1;
                DecimalFormat df = new DecimalFormat("0000000000".substring(0, intStr.length()));
                String fseq = df.format(seq);
                ret = rest + fseq;
                if (log.isTraceEnabled()) {
                    log.trace((Object)("<incrementKeySequence: " + (String)ret));
                }
            } else {
                log.info((Object)("incrementKeySequence - Sequence does not contain any nummeric part: " + (String)ret));
            }
        }
        return ret;
    }

    private static String incrementNumeric(String s) {
        if (!s.matches("[0-9]{1,5}")) {
            return null;
        }
        int len = s.length();
        int incrSeq = Integer.parseInt(s, 10) + 1;
        if ((double)incrSeq == Math.pow(10.0, len)) {
            incrSeq = 0;
        }
        Object newSeq = "00000" + Integer.toString(incrSeq, 10);
        newSeq = ((String)newSeq).substring(((String)newSeq).length() - len);
        return ((String)newSeq).toUpperCase(Locale.ENGLISH);
    }

    private static String incrementAlphaNumeric(String s) {
        if (!s.matches("[0-9A-Z]{1,5}")) {
            return null;
        }
        int len = s.length();
        int incrSeq = Integer.parseInt(s, 36) + 1;
        if ((double)incrSeq == Math.pow(36.0, len)) {
            incrSeq = 0;
        }
        Object newSeq = "00000" + Integer.toString(incrSeq, 36);
        newSeq = ((String)newSeq).substring(((String)newSeq).length() - len);
        return ((String)newSeq).toUpperCase(Locale.ENGLISH);
    }

    public static Collection<String> splitURIs(String dPoints) {
        String dispPoints = dPoints.trim();
        LinkedList<String> result = new LinkedList<String>();
        for (int i = 0; i < dispPoints.length(); ++i) {
            int nextQ = dispPoints.indexOf(34, i);
            if (nextQ == i) {
                nextQ = dispPoints.indexOf(34, i + 1);
                if (nextQ == -1) {
                    nextQ = dispPoints.length();
                }
                result.add(dispPoints.substring(i + 1, nextQ).trim());
                i = nextQ;
                continue;
            }
            int nextSep = dispPoints.indexOf(59, i);
            if (nextSep == i) continue;
            if (nextSep != -1) {
                result.add(dispPoints.substring(i, nextSep).trim());
                i = nextSep;
                continue;
            }
            if (i >= dispPoints.length()) continue;
            result.add(dispPoints.substring(i).trim());
            break;
        }
        return result;
    }

    public static String[] parseCertData(String certdata) {
        if (certdata == null) {
            return null;
        }
        String dnStrings = "([a-zA-Z0-9]+|(([0-9]+\\.)*[0-9]+))";
        String[] formats = new String[]{"(^[0-9A-Fa-f]+), ?((([a-zA-Z0-9]+|(([0-9]+\\.)*[0-9]+))=[^,]+,)*(([a-zA-Z0-9]+|(([0-9]+\\.)*[0-9]+))=[^,]+)*)", "(^[0-9A-Fa-f]+) : DN : \"([^\"]*)\"( ?: SubjectDN : \"[^\"]*\")?"};
        String[] ret = null;
        for (String format : formats) {
            Pattern p = Pattern.compile(format);
            Matcher m = p.matcher(certdata);
            if (!m.find()) continue;
            ret = new String[]{m.group(1), m.group(2)};
            break;
        }
        return ret;
    }

    public static String getCleanXForwardedFor(String rawHeaderValue) {
        if (rawHeaderValue == null) {
            return null;
        }
        return rawHeaderValue.trim().toLowerCase().replaceAll("[^0-9a-f.,: ]", "?");
    }

    public static String getAsStringWithSeparator(String separator, Collection<?> values) {
        StringBuilder names = new StringBuilder();
        for (Object value : values) {
            if (names.length() != 0) {
                names.append(separator);
            }
            names.append(value);
        }
        return names.toString();
    }

    public static boolean containsCaseInsensitive(String[] l, String s) {
        for (String string : l) {
            if (!string.equalsIgnoreCase(s)) continue;
            return true;
        }
        return false;
    }

    public static List<Integer> idStringToListOfInteger(String ids, String listSeparator) {
        ArrayList<Integer> result = new ArrayList<Integer>();
        if (StringUtils.isNotEmpty((String)ids)) {
            for (String id : ids.split(listSeparator)) {
                result.add(Integer.valueOf(id));
            }
        }
        return result;
    }

    public static boolean checkFieldForLegalChars(String value) {
        String whiteList = "[\\u0041-\\u005a\\u0061-\\u007a\\u00a1-\\ud7ff\\ue000-\\uffff_ 0-9@\\.\\*\\,\\-:\\/\\?\\'\\=\\(\\)\\|.]+";
        return Pattern.matches("[\\u0041-\\u005a\\u0061-\\u007a\\u00a1-\\ud7ff\\ue000-\\uffff_ 0-9@\\.\\*\\,\\-:\\/\\?\\'\\=\\(\\)\\|.]+", value);
    }

    public static boolean isAlphaOrAsciiPrintable(String str) {
        if (str == null) {
            return false;
        }
        int sz = str.length();
        for (int i = 0; i < sz; ++i) {
            if (Character.isLetter(str.charAt(i)) || CharUtils.isAsciiPrintable((char)str.charAt(i))) continue;
            return false;
        }
        return true;
    }

    public static boolean isLesserThan(String first, String second) {
        if (log.isTraceEnabled()) {
            log.trace((Object)("isLesserThan(" + first + ", " + second + ")"));
        }
        String delimiter = "\\.";
        if (first == null) {
            if (second != null) {
                return true;
            }
            throw new IllegalArgumentException("First version argument may not be null");
        }
        if (second == null) {
            throw new IllegalArgumentException("Second version argument may not be null");
        }
        String[] firstSplit = first.split("\\.");
        String[] secondSplit = second.split("\\.");
        for (int i = 0; i < Math.max(firstSplit.length, secondSplit.length); ++i) {
            String secondString;
            String firstString;
            String regex = "[^0-9].*";
            if (i >= firstSplit.length) {
                firstString = "0";
                secondString = secondSplit[i].replaceAll(regex, "");
            } else if (i >= secondSplit.length) {
                firstString = firstSplit[i].replaceAll(regex, "");
                secondString = "0";
            } else {
                firstString = firstSplit[i].replaceAll(regex, "");
                secondString = secondSplit[i].replaceAll(regex, "");
            }
            if (firstString.isEmpty()) {
                firstString = "0";
            }
            if (secondString.isEmpty()) {
                secondString = "0";
            }
            if (StringUtils.isNumeric((String)firstString) && StringUtils.isNumeric((String)secondString)) {
                int secondNumber;
                int firstNumber = Integer.parseInt(firstString);
                if (firstNumber == (secondNumber = Integer.parseInt(secondString))) continue;
                return firstNumber < secondNumber;
            }
            throw new IllegalArgumentException("Unable to parse version numbers.");
        }
        return false;
    }

    public static String normalizeNewlines(String s) {
        return s != null ? windowsOrMacNewlines.matcher(s).replaceAll("\n") : null;
    }

    public static String[] splitByNewlines(String s) {
        return StringTools.normalizeNewlines(s).split("\n");
    }

    public static String hex(byte[] data) {
        if (data == null) {
            return null;
        }
        return Hex.toHexString((byte[])data);
    }

    public static <T extends Comparable<T>> int compare(T a, T b) {
        if (a == null) {
            return -1;
        }
        if (b == null) {
            return 1;
        }
        return a.compareTo(b);
    }

    public static String capitalizeCountryCodeInSubjectDN(String subjectDN) {
        String delimiter = "C=";
        int delimeterStartIndex = subjectDN.indexOf(delimiter);
        if (delimeterStartIndex > -1) {
            boolean isC;
            int countryStartIndex = delimeterStartIndex + delimiter.length();
            boolean bl = isC = delimeterStartIndex == 0 || subjectDN.charAt(delimeterStartIndex - 1) == ' ' || subjectDN.charAt(delimeterStartIndex - 1) == ',';
            if (delimeterStartIndex != -1 && isC) {
                int countryEndIndex = countryStartIndex + 2;
                String replacement = subjectDN.substring(countryStartIndex, countryEndIndex).toUpperCase(Locale.ENGLISH);
                String manipulatedSubjectDN = subjectDN.substring(0, countryStartIndex) + replacement + subjectDN.substring(countryEndIndex);
                return manipulatedSubjectDN;
            }
        }
        return subjectDN;
    }

    public static boolean checkValueIsAlfaNumericWithSpecialChars(String value) {
        String whiteList = "[a-zA-Z0-9-_\\s\\.]+";
        return Pattern.matches("[a-zA-Z0-9-_\\s\\.]+", value);
    }

    public static String trim(String str) {
        return str == null ? null : str.trim();
    }

    public static String trimUnescaped(String str) {
        if (str == null) {
            return null;
        }
        return str.replaceAll("(^\\s+)|((?<!\\\\)\\s+$)", "");
    }

    static {
        try {
            VALID_IPV4_PATTERN = Pattern.compile(ipv4Pattern, 2);
            VALID_IPV6_PATTERN = Pattern.compile(ipv6Pattern, 2);
            VALID_RFC5322_USER_PART = Pattern.compile(emailUserPart, 2);
            VALID_RFC5322_EMAIL = Pattern.compile(email, 2);
        }
        catch (PatternSyntaxException e) {
            log.error((Object)"Unable to compile IP address validation pattern", (Throwable)e);
        }
        STRIP_XSS = new CharSet(new char[]{'<', '>'});
        STRIP_SQL_CHARS = new CharSet(new char[]{'\'', '\"', '\n', '\r', '\\', ';', '&', '|', '!', '\u0000', '%', '`', '<', '>', '?', '$', '~'});
        STRIP_SDATT_STRIP_CHARS = new CharSet(new char[]{'\n', '\r', '\\', ';', '&', '|', '!', '\u0000', '%', '`', '<', '>', '?', '$', '~'});
        STRIP_SQL_CHARS_SINGLE_QUOTE_ESCAPED = new CharSet(new char[]{'\"', '\n', '\r', '\\', ';', '|', '!', '\u0000', '%', '`', '<', '>', '?', '$', '~'});
        STRIP_FILENAME_CHARS = new CharSet(new char[]{'\u0000', '\n', '\r', '/', '\\', '?', '%', '$', '*', ':', ';', '|', '\"', '\'', '`', '<', '>'});
        ALLOWED_ESCAPE_CHARS = new CharSet(new char[]{',', '\"', '\\', '+', '<', '>', ';', '=', '#', ' '});
        WS = Pattern.compile("\\s+");
        SPACE_AND_COLON = Pattern.compile("[: ]");
    }

    public static class CharSet {
        public static volatile CharSet INSTANCE = new CharSet(StringConfigurationCache.INSTANCE.getForbiddenCharacters());
        private Set<Character> charSet = null;

        private CharSet(char[] array) {
            HashSet<Character> set = new HashSet<Character>();
            for (char c : array) {
                set.add(Character.valueOf(c));
            }
            this.charSet = set;
        }

        boolean contains(char c) {
            return this.charSet.contains(Character.valueOf(c));
        }

        public static void reset() {
            INSTANCE = new CharSet(StringConfigurationCache.INSTANCE.getForbiddenCharacters());
        }
    }
}

