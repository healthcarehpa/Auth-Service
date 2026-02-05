package com.healthcare.auth.util;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RsaKeyLoader {

    public static RSAPrivateKey loadPrivateKeyv0(String path) throws Exception {
        String key = Files.readString(Paths.get(path))
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);

        return (RSAPrivateKey) KeyFactory.getInstance("RSA")
                .generatePrivate(spec);
    }

    public static RSAPrivateKey loadPrivateKey(InputStream is) throws Exception {

        String key = new String(is.readAllBytes(), StandardCharsets.UTF_8)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] decoded = Base64.getDecoder().decode(key);

        PKCS8EncodedKeySpec spec =
                new PKCS8EncodedKeySpec(decoded);

        return (RSAPrivateKey) KeyFactory
                .getInstance("RSA")
                .generatePrivate(spec);
    }

    public static RSAPrivateKey loadPrivateKey(String path) throws Exception {

        String key = Files.readString(Paths.get(path))
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] decoded = Base64.getDecoder().decode(key);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);

        return (RSAPrivateKey) KeyFactory.getInstance("RSA")
                .generatePrivate(spec);
    }


    public static RSAPublicKey loadPublicKey(String path) throws Exception {
        String key = Files.readString(Paths.get(path))
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);

        return (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(spec);
    }
}

