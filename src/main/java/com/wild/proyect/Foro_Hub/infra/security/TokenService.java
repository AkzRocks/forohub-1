package com.wild.proyect.Foro_Hub.infra.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.wild.proyect.Foro_Hub.domain.user.Usuario;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {

    @Value("${api.security.secret}")
    private String apiSecret;

    public String generateToken(Usuario usuario) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(apiSecret);
            return JWT.create()
                    .withIssuer("Foro-hub")
                    .withSubject(usuario.getClass().getName())
                    .withClaim("id", usuario.getClass().getName())
                    .withExpiresAt(generarFechaExpiracion())
                    .sign(algorithm);
        } catch (JWTCreationException exception) {
            throw new RuntimeException("Error creating token", exception);
        }
    }

    public String getSubject(String token) {
        if (token == null) {
            throw new RuntimeException("Token is null");
        }

        DecodedJWT decodedJWT;
        try {
            Algorithm algorithm = Algorithm.HMAC256(apiSecret);
            decodedJWT = JWT.require(algorithm)
                    .withIssuer("foro hub")
                    .build()
                    .verify(token);
        } catch (JWTVerificationException exception) {
            throw new RuntimeException("Token verification failed", exception);
        }

        String subject = decodedJWT.getSubject();
        if (subject == null) {
            throw new RuntimeException("Verifier subject is null");
        }

        return subject;
    }

    private Instant generarFechaExpiracion() {
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.ofHours(-5));
    }
}