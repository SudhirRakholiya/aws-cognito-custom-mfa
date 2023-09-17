package com.springboot.cognito.exception;
public class AwsSnsClientException extends RuntimeException {

    /**
     * Aws Client Exception with error message and throwable
     *
     * @param errorMessage error message
     * @param throwable    error
     */
    public AwsSnsClientException(String errorMessage, Throwable throwable) {
        super(errorMessage, throwable);
    }

}