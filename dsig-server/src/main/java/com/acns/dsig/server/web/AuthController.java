package com.acns.dsig.server.web;

import com.acns.dsig.server.service.UserService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/register")
    public String register() {
        return "register";
    }

    @PostMapping("/register")
    public String processRegister(
            @RequestParam("username") String username,
            @RequestParam("password") String password,
            @RequestParam(value = "role", defaultValue = "ROLE_VERIFIER") String role,
            Model model
    ) {
        try {
            String sanitizedRole = role != null ? role.trim().toUpperCase() : "ROLE_VERIFIER";
            if (!"ROLE_VERIFIER".equals(sanitizedRole) && !"ROLE_SIGNER".equals(sanitizedRole)) {
                throw new IllegalArgumentException("Invalid registration role. Only Verifier and Signer roles are eligible for self-registration.");
            }
            userService.registerUser(username, password, sanitizedRole);
            return "redirect:/login?registered";
        } catch (IllegalArgumentException e) {
            model.addAttribute("error", e.getMessage());
            return "register";
        }
    }
}
