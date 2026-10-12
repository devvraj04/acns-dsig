package com.acns.dsig.server.web;

import com.acns.dsig.server.persistence.User;
import com.acns.dsig.server.service.HistoryService;
import com.acns.dsig.server.service.KeyManagementService;
import com.acns.dsig.server.service.TrustStoreService;
import com.acns.dsig.server.service.UserService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DashboardController {

    private final UserService userService;
    private final KeyManagementService keyManagementService;
    private final TrustStoreService trustStoreService;
    private final HistoryService historyService;

    public DashboardController(
            UserService userService,
            KeyManagementService keyManagementService,
            TrustStoreService trustStoreService,
            HistoryService historyService
    ) {
        this.userService = userService;
        this.keyManagementService = keyManagementService;
        this.trustStoreService = trustStoreService;
        this.historyService = historyService;
    }

    @GetMapping({"/", "/dashboard"})
    public String dashboard(@AuthenticationPrincipal UserDetails userDetails, Model model) {
        if (userDetails != null) {
            User user = userService.findByUsername(userDetails.getUsername()).orElse(null);
            if (user != null) {
                model.addAttribute("user", user);
                model.addAttribute("keyCount", keyManagementService.getKeysForUser(user.getId()).size());
                model.addAttribute("trustCount", trustStoreService.getSignersForUser(user.getId()).size());
                model.addAttribute("historyCount", historyService.getHistoryForUser(user.getId()).size());
            }
        }
        model.addAttribute("engineInfo", new com.acns.dsig.core.crypto.SignatureService().describeEngine());
        return "dashboard";
    }
}
