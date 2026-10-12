package com.acns.dsig.server.web;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("demo")
@DisplayName("ApiController — REST Endpoints Integration Tests")
class ApiControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void testHealthCheck() throws Exception {
        mockMvc.perform(get("/api/health"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.system").value("ACNS-DSIG Server"))
                .andExpect(jsonPath("$.algorithms.hash").value("SHA-256"))
                .andExpect(jsonPath("$.algorithms.rsaModulusBits").value(3072));
    }

    @Test
    void testSignatureEngineInfo() throws Exception {
        mockMvc.perform(get("/api/signature-engine"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.signatureAlgorithm").value("RSASSA-PSS"))
                .andExpect(jsonPath("$.manifestAlgorithmId").value("RSASSA-PSS-SHA256-MGF1SHA256-S32"))
                .andExpect(jsonPath("$.hashAlgorithm").value("SHA-256"))
                .andExpect(jsonPath("$.minRsaKeyBits").value(3072))
                .andExpect(jsonPath("$.saltLengthBytes").value(32));
    }

    @Test
    void testSignatureEngineBenchmark() throws Exception {
        mockMvc.perform(get("/api/signature-engine/benchmark"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.iterations").value(25))
                .andExpect(jsonPath("$.allSignaturesValid").value(true))
                .andExpect(jsonPath("$.keyBits").value(3072))
                .andExpect(jsonPath("$.scheme").value("RSASSA-PSS"));
    }
}
