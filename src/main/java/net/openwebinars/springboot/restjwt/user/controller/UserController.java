package net.openwebinars.springboot.restjwt.user.controller;

import lombok.RequiredArgsConstructor;
import net.openwebinars.springboot.restjwt.security.jwt.access.JwtProvider;
import net.openwebinars.springboot.restjwt.security.jwt.refresh.RefreshToken;
import net.openwebinars.springboot.restjwt.security.jwt.refresh.RefreshTokenException;
import net.openwebinars.springboot.restjwt.security.jwt.refresh.RefreshTokenRequest;
import net.openwebinars.springboot.restjwt.security.jwt.refresh.RefreshTokenService;
import net.openwebinars.springboot.restjwt.user.dto.*;
import net.openwebinars.springboot.restjwt.user.model.User;
import net.openwebinars.springboot.restjwt.user.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final AuthenticationManager authManager;
    private final JwtProvider jwtProvider;
    private final RefreshTokenService refreshTokenService;

    @PostMapping("/auth/register")
    public ResponseEntity<UserResponse> createUserWithUserRole(@RequestBody CreateUserRequest createUserRequest) {
        User user = userService.createUserWithUserRole(createUserRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(UserResponse.fromUser(user));
    }

    // Later we can handle the security of access to this request

    @PostMapping("/auth/register/admin")
    public ResponseEntity<UserResponse> createUserWithAdminRole(@RequestBody CreateUserRequest createUserRequest) {
        User user = userService.createUserWithAdminRole(createUserRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(UserResponse.fromUser(user));
    }


    @PostMapping("/auth/login")
    public ResponseEntity<JwtUserResponse> login(@RequestBody LoginRequest loginRequest) {

        // We perform authentication

        Authentication authentication =
                authManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                loginRequest.getUsername(),
                                loginRequest.getPassword()
                        )
                );

        // Once done, we save it in the security context
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // We return an appropriate response
        String token = jwtProvider.generateToken(authentication);

        User user = (User) authentication.getPrincipal();

        // We remove the token (if it exists) before creating it,
        // since each user should only have one concurrent refresh token
        refreshTokenService.deleteByUser(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(JwtUserResponse.of(user, token, refreshToken.getToken()));


    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        String refreshToken = refreshTokenRequest.getRefreshToken();

        return refreshTokenService.findByToken(refreshToken)
                .map(refreshTokenService::verify)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String token = jwtProvider.generateToken(user);
                    refreshTokenService.deleteByUser(user);
                    RefreshToken refreshToken2 = refreshTokenService.createRefreshToken(user);
                    return ResponseEntity.status(HttpStatus.CREATED)
                            .body(JwtUserResponse.builder()
                                    .token(token)
                                    .refreshToken(refreshToken2.getToken())
                                    .build());
                })
                .orElseThrow(() -> new RefreshTokenException("Refresh token not found"));

    }

    @PutMapping("/user/changePassword")
    public ResponseEntity<UserResponse> changePassword(@RequestBody ChangePasswordRequest changePasswordRequest,
                                                       @AuthenticationPrincipal User loggedUser) {

        // This code can be improved.
        // Validation of the new password can be done with a validator.
        // Error handling can be done with its own exceptions
        try {
            if (userService.passwordMatch(loggedUser, changePasswordRequest.getOldPassword())) {
                Optional<User> modified = userService.editPassword(loggedUser.getId(), changePasswordRequest.getNewPassword());
                if (modified.isPresent())
                    return ResponseEntity.ok(UserResponse.fromUser(modified.get()));
            } else {
                // Ideally this should be managed centrally
                // You can see how to do it in the training on Validation with Spring Boot
                // and training on Error Management with Spring Boot
                throw new RuntimeException();
            }
        } catch (RuntimeException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password Data Error");
        }

        return null;
    }


}
