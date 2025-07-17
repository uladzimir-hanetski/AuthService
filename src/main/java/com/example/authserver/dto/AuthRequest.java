package com.example.authserver.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class AuthRequest {

    @NotBlank(message = "Login can't be empty")
    @Size(min = 4, max = 64)
    private String login;

    @NotBlank(message = "Password can't be empty")
    @Size(min = 8, max = 64)
    private String password;
}
