package com.springboot.cognito.utils;

import org.springframework.http.HttpStatus;

public class CommonMessages {
	
	// custom messages

	public static final String USER_REGISTER_SUCCESS = "User registered successfully";
	public static final String EXCEEPTION_MESSAGE = "Something went wrong while processing the request";
	public static final String SMS_MFS_SEND = "Verification Code sent to your registered number";
	public static final String SIGN_IN_SUCCESS = "Sign-In success";
	public static final String INVALID_USER = "Incorrect Username or Password";
	public static final String VERIFICATION_CODE_SEND_MOBILE = "Verification code has been sent to your registered mobile";
	public static final String VERIFICATION_CODE_SEND_EMAIL = "Verification code has been sent to your registered email";
	public static final String VERIFICATION_SUCCESS = "Verification success";
	public static final String MFA_ENABLED = "You have successfully enabled two-factor authentication";
	public static final String MFA_DISABLED = "You have successfully disabled two-factor authentication";
	public static final String INVALID_ATTRIBUTE = "Invalid Attribute Value";
	public static final String INVALID_CODE = "Invalid Code";
	public static final String SESSION_EXPIRED = "Invalid session for the user, session is expired";
	public static final String MFA_CODE_EXPIRED = "Verification Code is Expired";
	public static final String VERIFICATION_CODE_SEND_ON = "Verification code has been sent to your registered ";
	public static final String REQUIRED_ADDITIONAL_VERIFICATION = "Authentication requires additional MFA verification";
	
	// HTTP Status Codes

	public static final String OK = String.valueOf(HttpStatus.OK.value());
	public static final String NOT_FOUND = String.valueOf(HttpStatus.NOT_FOUND.value());
	public static final String DUPLICATE_DATA = String.valueOf(HttpStatus.CONFLICT.value());
	public static final String INVALID_DATA = String.valueOf(HttpStatus.UNPROCESSABLE_ENTITY.value());
	public static final String BAD_REQUEST = String.valueOf(HttpStatus.BAD_REQUEST.value());
	public static final String UNAUTHORIZED = String.valueOf(HttpStatus.UNAUTHORIZED.value());
	public static final String INTERNAL_SERVER_ERROR = String.valueOf(HttpStatus.INTERNAL_SERVER_ERROR.value());
}
