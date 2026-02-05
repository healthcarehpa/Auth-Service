package com.healthcare.auth;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.SecretKey;
import java.util.Base64;

@SpringBootApplication
public class AuthLoginServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthLoginServiceApplication.class, args);
        //SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        //System.out.println("Password: " + Base64.getEncoder().encodeToString(key.getEncoded()));

    }

}
