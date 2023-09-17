package com.springboot.cognito.dto;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;

@Data
public class VerifyUserAttributeDto {

	private String attributeName;
	private String userCode;
	private String username;
	@JsonProperty
	private boolean isEnable;
}