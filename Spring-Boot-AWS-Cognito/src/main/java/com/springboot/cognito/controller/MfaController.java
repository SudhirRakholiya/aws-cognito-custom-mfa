package com.springboot.cognito.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Description;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.springboot.cognito.dto.EnableMFADto;
import com.springboot.cognito.dto.VerifyUserAttributeDto;
import com.springboot.cognito.service.UserService;

@RestController
public class MfaController {

	@Autowired
	private UserService usersService;
	
	@Description("This API is for enable MFA") 
	@PostMapping(path = "/enable-mfa")
    public ResponseEntity<?> enableMfa(HttpServletRequest request,@RequestBody EnableMFADto enableMFADto) {
		return ResponseEntity.ok().body(usersService.enableMFA(request,enableMFADto));
	}
	
	@Description("This API is to get UserAttribute VerificationCode")
	@PostMapping(path = "/get-user-attribute-verification-code")
	public ResponseEntity<?> getUserAttributeVerificationCode(HttpServletRequest request, @RequestBody EnableMFADto enableMFADto) {
		return ResponseEntity.ok().body(usersService.getAttributeVerificationCode(request, enableMFADto));
	}
	
	@Description("This API is for verify UserAttribute")
	@PostMapping(path = "/verify-user-attribute")
	public ResponseEntity<?> verifyUserAttribute(HttpServletRequest request,
			@RequestBody VerifyUserAttributeDto verifyUserAttributeDto) {
		return ResponseEntity.ok().body(usersService.verifyUserAttribute(request, verifyUserAttributeDto));
	}

}
