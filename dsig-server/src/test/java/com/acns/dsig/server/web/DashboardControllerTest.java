package com.acns.dsig.server.web;

import com.acns.dsig.server.service.UserService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("demo")
@DisplayName("DashboardController — UI Integration Tests")
class DashboardControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserService userService;

    @Test
    @WithMockUser(username = "alice", roles = "SIGNER")
    void testDashboardLoadsForExistingUserWithoutExtraButtons() throws Exception {
        if (userService.findByUsername("alice").isEmpty()) {
            userService.registerUser("alice", "Password123!", "ROLE_SIGNER");
        }
        mockMvc.perform(get("/dashboard"))
                .andExpect(status().isOk())
                .andExpect(view().name("dashboard"))
                .andExpect(content().string(containsString("Logout")))
                // Ensure Login and Register extra buttons are NOT rendered for authenticated user
                .andExpect(content().string(not(containsString(">Login</a>"))))
                .andExpect(content().string(not(containsString(">Register</a>"))))
                // Ensure non-admin users do not see Audit link
                .andExpect(content().string(not(containsString(">Audit</a>"))));
    }

    @Test
    @WithMockUser(username = "admin_user", roles = "ADMIN")
    void testDashboardShowsAuditLinkForAdmin() throws Exception {
        mockMvc.perform(get("/dashboard"))
                .andExpect(status().isOk())
                .andExpect(view().name("dashboard"))
                .andExpect(content().string(containsString("Logout")))
                .andExpect(content().string(containsString(">Audit</a>")));
    }

    @Test
    @WithMockUser(username = "nonexistent_user", roles = "VERIFIER")
    void testDashboardLoadsForNonExistentUser() throws Exception {
        mockMvc.perform(get("/dashboard"))
                .andExpect(status().isOk())
                .andExpect(view().name("dashboard"));
    }

    @Test
    void testUnauthenticatedNavbarShowsLoginRegisterAndHidesLogout() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(content().string(containsString(">Login</a>")))
                .andExpect(content().string(containsString(">Register</a>")))
                .andExpect(content().string(not(containsString("Logout"))))
                .andExpect(content().string(not(containsString(">Dashboard</a>"))))
                .andExpect(content().string(not(containsString(">Audit</a>"))));
    }
}
