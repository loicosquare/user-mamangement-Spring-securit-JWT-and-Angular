package com.example.demoFinalmaven.constant;

public class SecurityConstant {
    public static final  long EXPIRATION_TIME = 432_000_000; //5 days expressed in milliseconds.
    public static final String TOKEN_PREFIX = "Bearer";
    public static final String JWT_TOKEN_HEADER = "Jwt-Token"; //Our default custum header like httpHeader.
    public static final String TOKEN_CANNOT_BE_VERIFIED = "Token cannot be verified";
    public static final String LOIC_SANOU_LLC = "Loic Sanou, LLC"; //The name of the company.
    public static final String LOIC_SANOU_ADMINISTRATION = "User management portal";
    public static final String AUTHORITIES = "Authorities"; //All of the authories of the user.
    public static final String FORBIDDEN_MESSAGE = "You need to log in to access this page";
    public static final String ACCES_DENIED_MESSAGE = "You do not have permission to access this page";
    public static final String OPTIONS_HTTP_METHOD = "OPTIONS";
    public static final String[] PUBLIC_URLS = {"/user/login", "/user/register", "/user/resetpassword/**", "/user/image/**"};
}
