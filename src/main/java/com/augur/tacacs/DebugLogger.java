package com.augur.tacacs;

/**
 * Very simple wrapper for debug logging.
 */
public interface DebugLogger {
    void debug(String msg);
    void error(String msg);
}
