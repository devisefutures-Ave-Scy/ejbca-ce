/*
 * Decompiled with CFR 0.152.
 */
package com.keyfactor;

import java.io.Serializable;

public class ErrorCode
implements Serializable {
    private static final long serialVersionUID = -5727877733175038546L;
    private String internalErrorCode = "NOT_SPECIFIED";
    private static final String _CA_NOT_EXISTS = "CA_NOT_EXISTS";
    private static final String _CA_ALREADY_EXISTS = "CA_ALREADY_EXISTS";
    private static final String _CA_MS_COMPATIBILITY_IRREVERSIBLE = "CA_MS_COMPATIBILITY_IRREVERSIBLE";
    private static final String _CA_ID_EQUALS_ZERO = "CA_ID_EQUALS_ZERO";
    private static final String _DELTA_CRL_NOT_AVAILABLE = "DELTA_CRL_NOT_AVAILABLE";
    private static final String _EE_PROFILE_NOT_EXISTS = "EE_PROFILE_NOT_EXISTS";
    private static final String _CERT_PROFILE_NOT_EXISTS = "CERT_PROFILE_NOT_EXISTS";
    private static final String _UNKOWN_TOKEN_TYPE = "UNKOWN_TOKEN_TYPE";
    private static final String _AUTH_CERT_NOT_RECEIVED = "AUTH_CERT_NOT_RECEIVED";
    private static final String _USER_NOT_FOUND = "USER_NOT_FOUND";
    private static final String _BAD_USER_TOKEN_TYPE = "BAD_USER_TOKEN_TYPE";
    private static final String _INVALID_CERTIFICATE = "INVALID_CERTIFICATE";
    private static final String _INVALID_KEY = "INVALID_KEY";
    private static final String _ILLEGAL_KEY = "ILLEGAL_KEY";
    private static final String _USER_WRONG_STATUS = "USER_WRONG_STATUS";
    private static final String _USER_ALREADY_EXISTS = "USER_ALREADY_EXISTS";
    private static final String _LOGIN_ERROR = "LOGIN_ERROR";
    private static final String _SIGNATURE_ERROR = "SIGNATURE_ERROR";
    private static final String _INVALID_KEY_SPEC = "INVALID_KEY_SPEC";
    private static final String _CERT_WRONG_STATUS = "CERT_WRONG_STATUS";
    private static final String _KEY_RECOVERY_NOT_AVAILABLE = "KEY_RECOVERY_NOT_AVAILABLE";
    private static final String _BAD_VALIDITY_FORMAT = "BAD_VALIDITY_FORMAT";
    private static final String _NOT_SUPPORTED_KEY_STORE = "NOT_SUPPORTED_KEY_STORE";
    private static final String _NOT_SUPPORTED_REQUEST_TYPE = "NOT_SUPPORTED_REQUEST_TYPE";
    private static final String _NOT_SUPPORTED_PIN_TYPE = "NOT_SUPPORTED_PIN_TYPE";
    private static final String _NOT_SUPPORTED_TOKEN_TYPE = "NOT_SUPPORTED_TOKEN_TYPE";
    private static final String _NOT_AUTHORIZED = "NOT_AUTHORIZED";
    private static final String _APPROVAL_WRONG_STATUS = "APPROVAL_WRONG_STATUS";
    private static final String _ENOUGH_APPROVAL = "ENOUGH_APPROVAL";
    private static final String _APPROVAL_ALREADY_EXISTS = "APPROVAL_ALREADY_EXISTS";
    private static final String _APPROVAL_REQUEST_ID_NOT_EXIST = "APPROVAL_REQUEST_ID_NOT_EXIST";
    private static final String _INVALID_LOG_LEVEL = "INVALID_LOG_LEVEL";
    private static final String _INTERNAL_ERROR = "INTERNAL_ERROR";
    private static final String _NOT_SPECIFIED = "NOT_SPECIFIED";
    private static final String _CA_OFFLINE = "CA_OFFLINE";
    private static final String _CA_INVALID_TOKEN_PIN = "CA INVALID TOKEN PIN";
    private static final String _ALREADY_REVOKED = "ALREADY_REVOKED";
    private static final String _CERT_PATH_INVALID = "CERT_PATH_INVALID";
    private static final String _CERT_COULD_NOT_BE_PARSED = "CERT_COULD_NOT_BE_PARSED";
    private static final String _CERTIFICATE_FOR_THIS_KEY_ALREADY_EXISTS_FOR_ANOTHER_USER = "CERTIFICATE_FOR_THIS_KEY_ALREADY_EXISTS_FOR_ANOTHER_USER";
    private static final String _CERTIFICATE_FOR_THIS_KEY_ALREADY_EXISTS = "CERTIFICATE_FOR_THIS_KEY_ALREADY_EXISTS";
    private static final String _CERTIFICATE_WITH_THIS_SUBJECTDN_ALREADY_EXISTS_FOR_ANOTHER_USER = "CERTIFICATE_WITH_THIS_SUBJECTDN_ALREADY_EXISTS_FOR_ANOTHER_USER";
    private static final String _SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS = "SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS";
    private static final String _FIELD_VALUE_NOT_VALID = "_FIELD_VALUE_NOT_VALID";
    private static final String _REVOKE_BACKDATE_NOT_ALLOWED = "REVOKE_BACKDATE_NOT_ALLOWED";
    private static final String _DATE_NOT_VALID = "DATE_NOT_VALID";
    private static final String _CRYPTOTOKEN_NAME_IN_USE = "CRYPTOTOKEN_NAME_IN_USE";
    private static final String _INTERNAL_KEY_BINDING_NAME_IN_USE = "INTERNAL_KEY_BINDING_NAME_IN_USE";
    private static final String _INTERNAL_KEY_BINDING_NONCE_CONFLICT = "INTERNAL_KEY_BINDING_NONCE_CONFLICT";
    private static final String _CERTIFICATE_IMPORT = "CERTIFICATE_IMPORT";
    private static final String _NAMECONSTRAINT_VIOLATION = "NAMECONSTRAINT_VIOLATION";
    private static final String _UNKNOWN_PROFILE_TYPE = "UNKNOWN_PROFILE_TYPE";
    private static final String _UNSUPPORTED_METHOD = "UNSUPPORTED_METHOD";
    private static final String _SIGNED_BY_EXTERNAL_CA_NOT_SUPPORTED = "SIGNED_BY_EXTERNAL_CA_NOT_SUPPORTED";
    private static final String _BAD_CERTIFICATE_PROFILE_TYPE = "BAD_CERTIFICATE_PROFILE_TYPE";
    private static final String _ROLE_DOES_NOT_EXIST = "ROLE_DOES_NOT_EXIST";
    private static final String _BAD_REQUEST_SIGNATURE = "BAD_REQUEST_SIGNATURE";
    private static final String _CA_NAME_CHANGE_RENEWAL_ERROR = "CA_NAME_CHANGE_RENEWAL_ERROR";
    private static final String _USER_DOESNT_FULFILL_END_ENTITY_PROFILE = "USER_DOESNT_FULFILL_END_ENTITY_PROFILE";
    private static final String _CUSTOM_CERTIFICATE_EXTENSION_ERROR = "CUSTOM_CERTIFICATE_EXTENSION_ERROR";
    private static final String _REFERENCES_TO_ITEM_EXIST = "REFERENCES_TO_ITEM_EXIST";
    private static final String _CMS_CERTIFICATE_PATH_MISSING = "CMS_CERTIFICATE_PATH_MISSING";
    private static final String _CAA_VALIDATION_FAILED = "CAA_VALIDATION_FAILED";
    private static final String _VALIDATION_FAILED = "VALIDATION_FAILED";
    private static final String _DOMAIN_BLACKLIST_FILE_PARSING_FAILED = "DOMAIN_BLACKLIST_FILE_PARSING_FAILED";
    private static final String _ACME_EAB_PARSING_FAILED = "ACME_EAB_PARSING_FAILED";
    private static final String _BAD_REQUEST = "BAD_REQUEST";
    public static final ErrorCode CA_NOT_EXISTS = new ErrorCode("CA_NOT_EXISTS");
    public static final ErrorCode CA_ALREADY_EXISTS = new ErrorCode("CA_ALREADY_EXISTS");
    public static final ErrorCode CA_MS_COMPATIBILITY_IRREVERSIBLE = new ErrorCode("CA_MS_COMPATIBILITY_IRREVERSIBLE");
    public static final ErrorCode CA_ID_EQUALS_ZERO = new ErrorCode("CA_ID_EQUALS_ZERO");
    public static final ErrorCode DELTA_CRL_NOT_AVAILABLE = new ErrorCode("DELTA_CRL_NOT_AVAILABLE");
    public static final ErrorCode EE_PROFILE_NOT_EXISTS = new ErrorCode("EE_PROFILE_NOT_EXISTS");
    public static final ErrorCode CERT_PROFILE_NOT_EXISTS = new ErrorCode("CERT_PROFILE_NOT_EXISTS");
    public static final ErrorCode UNKOWN_TOKEN_TYPE = new ErrorCode("UNKOWN_TOKEN_TYPE");
    public static final ErrorCode AUTH_CERT_NOT_RECEIVED = new ErrorCode("AUTH_CERT_NOT_RECEIVED");
    public static final ErrorCode USER_NOT_FOUND = new ErrorCode("USER_NOT_FOUND");
    public static final ErrorCode BAD_USER_TOKEN_TYPE = new ErrorCode("BAD_USER_TOKEN_TYPE");
    public static final ErrorCode INVALID_CERTIFICATE = new ErrorCode("INVALID_CERTIFICATE");
    public static final ErrorCode INVALID_KEY = new ErrorCode("INVALID_KEY");
    public static final ErrorCode ILLEGAL_KEY = new ErrorCode("ILLEGAL_KEY");
    public static final ErrorCode USER_WRONG_STATUS = new ErrorCode("USER_WRONG_STATUS");
    public static final ErrorCode USER_ALREADY_EXISTS = new ErrorCode("USER_ALREADY_EXISTS");
    public static final ErrorCode LOGIN_ERROR = new ErrorCode("LOGIN_ERROR");
    public static final ErrorCode SIGNATURE_ERROR = new ErrorCode("SIGNATURE_ERROR");
    public static final ErrorCode INVALID_KEY_SPEC = new ErrorCode("INVALID_KEY_SPEC");
    public static final ErrorCode CERT_WRONG_STATUS = new ErrorCode("CERT_WRONG_STATUS");
    public static final ErrorCode KEY_RECOVERY_NOT_AVAILABLE = new ErrorCode("KEY_RECOVERY_NOT_AVAILABLE");
    public static final ErrorCode BAD_VALIDITY_FORMAT = new ErrorCode("BAD_VALIDITY_FORMAT");
    public static final ErrorCode NOT_SUPPORTED_KEY_STORE = new ErrorCode("NOT_SUPPORTED_KEY_STORE");
    public static final ErrorCode NOT_SUPPORTED_REQUEST_TYPE = new ErrorCode("NOT_SUPPORTED_REQUEST_TYPE");
    public static final ErrorCode NOT_SUPPORTED_PIN_TYPE = new ErrorCode("NOT_SUPPORTED_PIN_TYPE");
    public static final ErrorCode NOT_SUPPORTED_TOKEN_TYPE = new ErrorCode("NOT_SUPPORTED_TOKEN_TYPE");
    public static final ErrorCode NOT_AUTHORIZED = new ErrorCode("NOT_AUTHORIZED");
    public static final ErrorCode APPROVAL_WRONG_STATUS = new ErrorCode("APPROVAL_WRONG_STATUS");
    public static final ErrorCode ENOUGH_APPROVAL = new ErrorCode("ENOUGH_APPROVAL");
    public static final ErrorCode APPROVAL_ALREADY_EXISTS = new ErrorCode("APPROVAL_ALREADY_EXISTS");
    public static final ErrorCode APPROVAL_REQUEST_ID_NOT_EXIST = new ErrorCode("APPROVAL_REQUEST_ID_NOT_EXIST");
    public static final ErrorCode INVALID_LOG_LEVEL = new ErrorCode("INVALID_LOG_LEVEL");
    public static final ErrorCode INTERNAL_ERROR = new ErrorCode("INTERNAL_ERROR");
    public static final ErrorCode NOT_SPECIFIED = new ErrorCode("NOT_SPECIFIED");
    public static final ErrorCode CA_OFFLINE = new ErrorCode("CA_OFFLINE");
    public static final ErrorCode CA_INVALID_TOKEN_PIN = new ErrorCode("CA INVALID TOKEN PIN");
    public static final ErrorCode ALREADY_REVOKED = new ErrorCode("ALREADY_REVOKED");
    public static final ErrorCode CERT_PATH_INVALID = new ErrorCode("CERT_PATH_INVALID");
    public static final ErrorCode CERT_COULD_NOT_BE_PARSED = new ErrorCode("CERT_COULD_NOT_BE_PARSED");
    public static final ErrorCode CERTIFICATE_FOR_THIS_KEY_ALREADY_EXISTS_FOR_ANOTHER_USER = new ErrorCode("CERTIFICATE_FOR_THIS_KEY_ALREADY_EXISTS_FOR_ANOTHER_USER");
    public static final ErrorCode CERTIFICATE_FOR_THIS_KEY_ALREADY_EXISTS = new ErrorCode("CERTIFICATE_FOR_THIS_KEY_ALREADY_EXISTS");
    public static final ErrorCode CERTIFICATE_WITH_THIS_SUBJECTDN_ALREADY_EXISTS_FOR_ANOTHER_USER = new ErrorCode("CERTIFICATE_WITH_THIS_SUBJECTDN_ALREADY_EXISTS_FOR_ANOTHER_USER");
    public static final ErrorCode SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS = new ErrorCode("SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS");
    public static final ErrorCode FIELD_VALUE_NOT_VALID = new ErrorCode("_FIELD_VALUE_NOT_VALID");
    public static final ErrorCode REVOKE_BACKDATE_NOT_ALLOWED = new ErrorCode("REVOKE_BACKDATE_NOT_ALLOWED");
    public static final ErrorCode DATE_NOT_VALID = new ErrorCode("DATE_NOT_VALID");
    public static final ErrorCode CRYPTOTOKEN_NAME_IN_USE = new ErrorCode("CRYPTOTOKEN_NAME_IN_USE");
    public static final ErrorCode INTERNAL_KEY_BINDING_NAME_IN_USE = new ErrorCode("INTERNAL_KEY_BINDING_NAME_IN_USE");
    public static final ErrorCode INTERNAL_KEY_BINDING_NONCE_CONFLICT = new ErrorCode("INTERNAL_KEY_BINDING_NONCE_CONFLICT");
    public static final ErrorCode CERTIFICATE_IMPORT = new ErrorCode("CERTIFICATE_IMPORT");
    public static final ErrorCode NAMECONSTRAINT_VIOLATION = new ErrorCode("NAMECONSTRAINT_VIOLATION");
    public static final ErrorCode UNKNOWN_PROFILE_TYPE = new ErrorCode("UNKNOWN_PROFILE_TYPE");
    public static final ErrorCode UNSUPPORTED_METHOD = new ErrorCode("UNSUPPORTED_METHOD");
    public static final ErrorCode SIGNED_BY_EXTERNAL_CA_NOT_SUPPORTED = new ErrorCode("SIGNED_BY_EXTERNAL_CA_NOT_SUPPORTED");
    public static final ErrorCode BAD_CERTIFICATE_PROFILE_TYPE = new ErrorCode("BAD_CERTIFICATE_PROFILE_TYPE");
    public static final ErrorCode ROLE_DOES_NOT_EXIST = new ErrorCode("ROLE_DOES_NOT_EXIST");
    public static final ErrorCode BAD_REQUEST_SIGNATURE = new ErrorCode("BAD_REQUEST_SIGNATURE");
    public static final ErrorCode CA_NAME_CHANGE_RENEWAL_ERROR = new ErrorCode("CA_NAME_CHANGE_RENEWAL_ERROR");
    public static final ErrorCode USER_DOESNT_FULFILL_END_ENTITY_PROFILE = new ErrorCode("USER_DOESNT_FULFILL_END_ENTITY_PROFILE");
    public static final ErrorCode CUSTOM_CERTIFICATE_EXTENSION_ERROR = new ErrorCode("CUSTOM_CERTIFICATE_EXTENSION_ERROR");
    public static final ErrorCode REFERENCES_TO_ITEM_EXIST = new ErrorCode("REFERENCES_TO_ITEM_EXIST");
    public static final ErrorCode CMS_CERTIFICATE_PATH_MISSING = new ErrorCode("CMS_CERTIFICATE_PATH_MISSING");
    public static final ErrorCode CAA_VALIDATION_FAILED = new ErrorCode("CAA_VALIDATION_FAILED");
    public static final ErrorCode VALIDATION_FAILED = new ErrorCode("VALIDATION_FAILED");
    public static final ErrorCode BAD_REQUEST = new ErrorCode("BAD_REQUEST");
    public static final ErrorCode DOMAIN_BLACKLIST_FILE_PARSING_FAILED = new ErrorCode("DOMAIN_BLACKLIST_FILE_PARSING_FAILED");
    public static final ErrorCode ACME_EAB_PARSING_FAILED = new ErrorCode("ACME_EAB_PARSING_FAILED");

    private ErrorCode() {
    }

    private ErrorCode(String internalErrorCode) {
        this.internalErrorCode = internalErrorCode;
    }

    public String getInternalErrorCode() {
        return this.internalErrorCode;
    }

    public void setInternalErrorCode(String internalErrorCode) {
        this.internalErrorCode = internalErrorCode;
    }

    public boolean equals(Object obj) {
        if (obj != null && obj instanceof ErrorCode) {
            ErrorCode other = (ErrorCode)obj;
            return this.internalErrorCode.equals(other.internalErrorCode);
        }
        return false;
    }

    public String toString() {
        return "Internal EJBCA error code: " + this.internalErrorCode;
    }

    public int hashCode() {
        if (this.internalErrorCode != null) {
            return this.internalErrorCode.hashCode();
        }
        return 0;
    }
}

