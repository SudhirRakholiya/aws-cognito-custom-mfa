package com.springboot.cognito.dto;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class OutputResponseDTO {

    private boolean status;
    private Object data;
    private String message;
    private String statusCode;
}