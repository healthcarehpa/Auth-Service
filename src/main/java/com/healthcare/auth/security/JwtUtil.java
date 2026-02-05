package com.healthcare.auth.security;

import com.healthcare.auth.entity.User;
import com.healthcare.auth.util.RsaKeyLoader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class JwtUtil {

    private final SecretKey key;
    private final RSAPrivateKey privateKey;

    public JwtUtil(
            @Value("${jwt.private.key.location}") String keyLocation,
            @Value("${jwt.secret}") String secret
    ) throws Exception {
        this.privateKey = RsaKeyLoader.loadPrivateKey(resolveKey(keyLocation));
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }

    public String generateToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 86400000))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateTokenwRSA(User user) {

        Map<String, Object> headers = new HashMap<>();
        headers.put("typ", "JWT");
        headers.put("kid", "medivault-auth-key-1");

        return Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("kid", "medivault-auth-key-1")
                .setSubject(user.getEmail())
                .setIssuer("MediVault-Auth-Service")
                .setIssuedAt(new Date())
                .setAudience("healthReservation-api")
                //.claim("roles", List.of(user.getRole()))
                .claim("roles", List.of("CONSUMER"))
                .claim("name", user.getFullName())
                .setExpiration(new Date(System.currentTimeMillis() + 15 * 60 * 1000)) // 15 min
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    private InputStream resolveKey(String location) throws IOException {

        if (location.startsWith("classpath:")) {
            String path = location.replace("classpath:", "");
            InputStream is =
                    getClass().getClassLoader().getResourceAsStream(path);
            if (is == null) {
                throw new FileNotFoundException(
                        "Private key not found in classpath: " + path
                );
            }
            return is;
        }

        if (location.startsWith("file:")) {
            return Files.newInputStream(
                    Paths.get(location.replace("file:", ""))
            );
        }

        // default: filesystem path
        return Files.newInputStream(Paths.get(location));
    }
}
