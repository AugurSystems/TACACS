package com.augur.tacacs;

public class TacacsException extends RuntimeException {
    public TacacsException() {
    }

    public TacacsException(String message) {
        super(message);
    }

    public TacacsException(String message, Throwable cause) {
        super(message, cause);
    }

    public TacacsException(Throwable cause) {
        super(cause);
    }

    public TacacsException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
