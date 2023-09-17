package com.springboot.cognito.dto;

import javax.validation.constraints.NotNull;

import lombok.Data;

@Data
public class LoginRequestDTO {

	@NotNull(message = "Email cannot be null")
	private String email;
	private String password;
	private String otpType;
	
}