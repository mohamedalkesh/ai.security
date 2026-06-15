package com.aisec.backend;

import com.aisec.backend.entity.Role;
import com.aisec.backend.entity.UserAccount;
import com.aisec.backend.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.security.web.FilterChainProxy;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * End-to-end integration test for the settings endpoints and their RBAC rules.
 * Uses H2 in-memory DB via the "test" Spring profile.
 */
@SpringBootTest
@ActiveProfiles("test")
class SettingsControllerIntegrationTest {

    @Autowired WebApplicationContext ctx;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder encoder;
    @Autowired ObjectMapper mapper;
    @Autowired FilterChainProxy springSecurityFilterChain;

    MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(ctx)
                .addFilter(springSecurityFilterChain)
                .build();
        users.deleteAll();
        createUser("admin",  "admin@x.com",  "admin123",  Role.ADMIN);
        createUser("viewer", "viewer@x.com", "viewer123", Role.VIEWER);
    }

    private void createUser(String name, String email, String pass, Role role) {
        UserAccount u = new UserAccount();
        u.setUsername(name);
        u.setEmail(email);
        u.setFullName(name);
        u.setPasswordHash(encoder.encode(pass));
        u.setRole(role);
        users.save(u);
    }

    private String loginAndGetToken(String username, String password) throws Exception {
        MvcResult res = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(String.format("{\"username\":\"%s\",\"password\":\"%s\"}", username, password)))
                .andExpect(status().isOk())
                .andReturn();
        Map<?, ?> body = mapper.readValue(res.getResponse().getContentAsString(), Map.class);
        return (String) body.get("token");
    }

    @Test
    void unauthenticated_GET_is_rejected() throws Exception {
        // Spring Security's default behaviour for stateless JWT auth is to respond with
        // 403 when no credentials are presented (rather than 401). Either is acceptable —
        // the contract that matters is: unauthenticated access must NOT succeed.
        mvc.perform(get("/api/settings"))
                .andExpect(result -> {
                    int s = result.getResponse().getStatus();
                    if (s != 401 && s != 403) {
                        throw new AssertionError("Expected 401 or 403 but got " + s);
                    }
                });
    }

    @Test
    void viewer_can_read_settings() throws Exception {
        String token = loginAndGetToken("viewer", "viewer123");
        mvc.perform(get("/api/settings").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.settings").exists())
                .andExpect(jsonPath("$.settings.general.systemName").exists());
    }

    @Test
    void viewer_is_forbidden_from_updating_settings() throws Exception {
        String token = loginAndGetToken("viewer", "viewer123");
        mvc.perform(put("/api/settings")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ai\":{\"sensitivity\":99}}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void admin_can_update_and_reread_settings() throws Exception {
        String token = loginAndGetToken("admin", "admin123");

        String payload = "{\"general\":{\"systemName\":\"Custom Name\",\"organization\":\"Org X\",\"timezone\":\"UTC\"}," +
                         "\"ai\":{\"sensitivity\":42}}";

        mvc.perform(put("/api/settings")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.settings.general.systemName").value("Custom Name"))
                .andExpect(jsonPath("$.settings.ai.sensitivity").value(42))
                .andExpect(jsonPath("$.updatedBy").value("admin"));

        // Re-read must show the persisted value
        MvcResult res = mvc.perform(get("/api/settings").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();
        assertThat(res.getResponse().getContentAsString()).contains("Custom Name").contains("\"sensitivity\":42");
    }

    @Test
    void admin_can_reset_to_defaults() throws Exception {
        String token = loginAndGetToken("admin", "admin123");

        // Change something first
        mvc.perform(put("/api/settings")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"general\":{\"systemName\":\"X\"}}"))
                .andExpect(status().isOk());

        // Reset
        mvc.perform(post("/api/settings/reset").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.settings.general.systemName").value("MADRS"));
    }
}
