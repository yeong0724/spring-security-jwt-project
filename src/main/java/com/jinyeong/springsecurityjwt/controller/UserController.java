package com.jinyeong.springsecurityjwt.controller;

import com.jinyeong.springsecurityjwt.domain.UserJoin;
import com.jinyeong.springsecurityjwt.service.UserService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/join")
    public String joinProcess(UserJoin userJoin) {
        System.out.println(userJoin.getUsername());
        userService.joinProcess(userJoin);
        return "ok";
    }
}