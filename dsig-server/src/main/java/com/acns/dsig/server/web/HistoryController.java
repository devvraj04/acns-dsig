package com.acns.dsig.server.web;

import com.acns.dsig.server.persistence.User;
import com.acns.dsig.server.persistence.VerificationRecord;
import com.acns.dsig.server.service.HistoryService;
import com.acns.dsig.server.service.UserService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

@Controller
@RequestMapping("/history")
public class HistoryController {

    private final HistoryService historyService;
    private final UserService userService;

    public HistoryController(HistoryService historyService, UserService userService) {
        this.historyService = historyService;
        this.userService = userService;
    }

    @GetMapping
    public String showHistory(@AuthenticationPrincipal UserDetails userDetails, Model model) {
        User user = userService.findByUsername(userDetails.getUsername()).orElseThrow();
        List<VerificationRecord> records = historyService.getHistoryForUser(user.getId());
        model.addAttribute("records", records);
        return "history";
    }
}
