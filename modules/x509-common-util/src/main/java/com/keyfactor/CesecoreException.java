/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  jakarta.xml.ws.WebFault
 */
package com.keyfactor;

import com.keyfactor.ErrorCode;
import jakarta.xml.ws.WebFault;

@WebFault
public class CesecoreException
extends Exception {
    private static final long serialVersionUID = -3754146611270578813L;
    ErrorCode errorCode = null;

    public CesecoreException() {
    }

    public CesecoreException(String message) {
        super(message);
    }

    public CesecoreException(ErrorCode errorCode) {
        this.errorCode = errorCode;
    }

    public CesecoreException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public CesecoreException(Exception exception) {
        super(exception);
        if (exception instanceof CesecoreException) {
            this.errorCode = ((CesecoreException)exception).getErrorCode();
        }
    }

    public CesecoreException(ErrorCode errorCode, Throwable exception) {
        super(exception);
        this.errorCode = errorCode;
    }

    public CesecoreException(String message, Throwable cause) {
        super(message, cause);
        if (cause instanceof CesecoreException) {
            this.errorCode = ((CesecoreException)cause).getErrorCode();
        }
    }

    public CesecoreException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return this.errorCode;
    }

    public void setErrorCode(ErrorCode errorCode) {
        this.errorCode = errorCode;
    }

    public static ErrorCode getErrorCode(Throwable exception) {
        if (exception == null) {
            return null;
        }
        if (exception instanceof CesecoreException) {
            return ((CesecoreException)exception).getErrorCode();
        }
        return CesecoreException.getErrorCode(exception.getCause());
    }
}

