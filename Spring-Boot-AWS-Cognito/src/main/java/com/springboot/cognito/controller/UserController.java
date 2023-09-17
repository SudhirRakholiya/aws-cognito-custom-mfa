package com.springboot.cognito.controller;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Description;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.springboot.cognito.dto.LoginRequestDTO;
import com.springboot.cognito.dto.OtpVerificaitonRequestDto;
import com.springboot.cognito.dto.SignUpDto;
import com.springboot.cognito.service.UserService;

@RestController
@RequestMapping("/user/api")
public class UserController {

	@Autowired
	private UserService usersService;
	
	@Description("This API is for sign-up")
	@PostMapping("/sign-up")
	public ResponseEntity<?> setUpUserProfile(@ModelAttribute SignUpDto signUpDto) {
		return ResponseEntity.ok(usersService.userSignUp(signUpDto));
	}
	
	@Description("This API is for user signIn")
	@PostMapping("/sign-in")
	public ResponseEntity<?> signIn(@RequestBody @Valid LoginRequestDTO loginRequestDTO) {
		return ResponseEntity.ok().body(usersService.userSignIn(loginRequestDTO));
	}
	
	@Description("This API is for initiate Sign in incase of MFA")
	@PostMapping("/initiate-custom-mfa-sign-in")
	public ResponseEntity<?> initiateUserSignInByEmailMFA(@RequestBody @Valid LoginRequestDTO loginRequestDTO) {
		return ResponseEntity.ok().body(usersService.initiateUserSignInByEmailMFA(loginRequestDTO));
	}
	
	@Description("This API is for verify code in Custom MFA")
	@PostMapping("/initiate-mfa-verification")
	public ResponseEntity<?> initiateEmailOtpVerification(
			@RequestBody OtpVerificaitonRequestDto otpVerificaitonRequestDto) {
		return ResponseEntity.ok().body(usersService.initiateEmailOtpVerification(otpVerificaitonRequestDto));
	}
}
