package com.example.demoFinalmaven.utility;

import com.auth0.jwt.JWT;
import com.example.demoFinalmaven.constant.SecurityConstant;
import com.example.demoFinalmaven.domain.UserPrincipal;
import org.springframework.beans.factory.annotation.Value;

import java.util.Date;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;

public class JWTTokenProvider {
    @Value("jwt.secret")
    private String secret;

    //This method is responsible to Generate the Token.
    public String generateJwtToken(UserPrincipal userPrincipal){
        String[] claims = getClaimsFromUser(userPrincipal);
        return JWT.create().withIssuer(SecurityConstant.LOIC_SANOU_LLC).withAudience(SecurityConstant.LOIC_SANOU_ADMINISTRATION)
                .withIssuedAt(new Date()).withSubject(userPrincipal.getUsername())
                .withArrayClaim(SecurityConstant.AUTHORITIES, claims)
                .withExpiresAt(new Date(System.currentTimeMillis() + SecurityConstant.EXPIRATION_TIME))
                .sign(HMAC512(secret.getBytes()));
    }

    private String[] getClaimsFromUser(UserPrincipal userPrincipal) {
    }

}
