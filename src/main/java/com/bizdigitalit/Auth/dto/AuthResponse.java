package com.bizdigitalit.Auth.dto;

import lombok.Data;

@Data
public class AuthResponse {
    private String accessToken;
    private String refreshToken; // 👈 add this field
}
