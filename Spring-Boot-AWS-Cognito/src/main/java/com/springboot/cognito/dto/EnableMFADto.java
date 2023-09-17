package com.springboot.cognito.dto;
import lombok.Data;

@Data
public class EnableMFADto {
	private String username;
	private String mobileNo;
	private String attributeName;
}