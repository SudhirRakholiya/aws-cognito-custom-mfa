package com.springboot.cognito.service;

import javax.servlet.http.HttpServletRequest;

import com.springboot.cognito.dto.EnableMFADto;
import com.springboot.cognito.dto.LoginRequestDTO;
import com.springboot.cognito.dto.OtpVerificaitonRequestDto;
import com.springboot.cognito.dto.OutputResponseDTO;
import com.springboot.cognito.dto.SignUpDto;
import com.springboot.cognito.dto.VerifyUserAttributeDto;

public interface UserService {
	
	public OutputResponseDTO userSignUp(SignUpDto signUpDto);
	
	public OutputResponseDTO userSignIn(LoginRequestDTO loginRequestDTO);
	
	public OutputResponseDTO enableMFA(HttpServletRequest request,EnableMFADto enableMFADto);
	
	public OutputResponseDTO getAttributeVerificationCode(HttpServletRequest request,EnableMFADto enableMFADto);
	
	public OutputResponseDTO verifyUserAttribute(HttpServletRequest request,VerifyUserAttributeDto verifyUserAttributeDto);
	
	public OutputResponseDTO initiateUserSignInByEmailMFA(LoginRequestDTO loginRequestDTO);
	
	public OutputResponseDTO initiateEmailOtpVerification(OtpVerificaitonRequestDto otpVerificaitonRequestDto);
}
