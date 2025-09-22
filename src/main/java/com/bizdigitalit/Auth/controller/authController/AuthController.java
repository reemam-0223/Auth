package com.bizdigitalit.Auth.controller;

import com.bizdigitalit.Auth.dto.SignInRequest;
import com.bizdigitalit.Auth.dto.SignupRequest;
import com.bizdigitalit.Auth.dto.AuthResponse;
import com.bizdigitalit.Auth.dto.RefreshTokenRequest;
import com.bizdigitalit.Auth.service.UserService;
import com.bizdigitalit.Auth.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final AuthService authService;

    public AuthController(UserService userService, AuthService authService) {
        this.userService = userService;
        this.authService = authService;
    }

    @PostMapping("/signup")
    public ResponseEntity<String> singUp(@Valid @RequestBody SignupRequest userSingUpDto){
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.addUser(userSingUpDto));
    }

    @PostMapping("/signin")
    public ResponseEntity<AuthResponse> signIn(@RequestBody SignInRequest userSignInDto){
        return ResponseEntity.ok(authService.signIn(userSignInDto));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@RequestBody RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();

        var user = authService.getUserByRefreshToken(refreshToken);

        if (authService.isRefreshTokenValid(refreshToken, user)) {
            String newAccessToken = authService.generateAccessToken(user);
            return ResponseEntity.ok(
                    AuthResponse.builder()
                            .accessToken(newAccessToken)
                            .refreshToken(refreshToken) // reuse or generate new one
                            .build()
            );
        } else {
            throw new RuntimeException("Refresh token expired, please login again");
        }
    }
}
