package com.example.controller;

import com.example.dto.request.UserRequest;
import com.example.dto.response.Response;
import com.example.model.User;
import com.example.security.DTO.AppUserDetail;
import com.example.security.JWT.JwtUtils;
import com.example.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    @Autowired
    UserService userService;
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    JwtUtils jwtUtils;
    @PostMapping("/login")
    public ResponseEntity<Response> login(@RequestBody UserRequest user, BindingResult errors, HttpServletResponse resp) {
        if(errors.hasErrors()) {
            return null;
        }
        User loginUser= userService.findUserById(user.getId());
        if(!passwordEncoder.matches(user.getPassword(), loginUser.getPassword())) {
            return new ResponseEntity("Đăng nhập thất bại",HttpStatus.NOT_FOUND);
        }

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getId().toString(),user.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        AppUserDetail userDetail= (AppUserDetail) authentication.getPrincipal();

        String accessToken = jwtUtils.generateJwtToken(userDetail);
        String refreshToken= jwtUtils.generateRefreshJwtToken(userDetail);

        Cookie cookieAccessToken = new Cookie("accessToken", accessToken);
        Cookie cookieRefreshToken = new Cookie("refreshToken", refreshToken);

        resp.setHeader("Set-Cookie", "test=value; Path=/");
        resp.addCookie(cookieAccessToken);
        resp.addCookie(cookieRefreshToken);

        Map<String,Object> data = new HashMap<>();
        data.put("accessToken",accessToken);
        data.put("refreshToken",refreshToken);
        return new ResponseEntity<>(new Response("Đăng nhập thành công",data), HttpStatus.OK);
    }
}
