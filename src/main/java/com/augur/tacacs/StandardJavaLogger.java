package com.augur.tacacs;

import java.util.logging.Level;
import java.util.logging.Logger;

public class StandardJavaLogger implements DebugLogger {

    private final Logger logger;

    public StandardJavaLogger(String name) {
        logger = Logger.getLogger(name);
    }

    @Override
    public void debug(String msg) {
        logger.log(Level.FINE, msg);
    }

    @Override
    public void error(String msg) {
        logger.log(Level.SEVERE, msg);
    }

}
