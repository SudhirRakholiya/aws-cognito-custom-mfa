package com.springboot.cognito.dto;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class OtpVerificaitonRequestDto {

	private String username;
	private String mfaCode;
	private String sessionId;
}