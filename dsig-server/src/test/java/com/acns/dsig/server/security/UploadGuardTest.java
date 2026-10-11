package com.acns.dsig.server.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.MockMultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("UploadGuard — Secure File Upload & Isolated Storage Tests")
class UploadGuardTest {

    @TempDir
    Path tempDir;

    private UploadGuard uploadGuard;
    private static final long MAX_BYTES = 1024 * 1024; // 1 MB for test

    @BeforeEach
    void setUp() throws IOException {
        uploadGuard = new UploadGuard(tempDir.toString(), MAX_BYTES);
    }

    @Test
    @DisplayName("Valid file upload is saved in isolated temporary directory with .tmp extension")
    void validFile_savedSafely() throws IOException {
        MockMultipartFile file = new MockMultipartFile(
                "document",
                "contract.pdf",
                "application/pdf",
                "Valid document content".getBytes()
        );

        Path savedPath = uploadGuard.saveToIsolatedTempFile(file);

        assertNotNull(savedPath);
        assertTrue(Files.exists(savedPath));
        assertTrue(savedPath.startsWith(tempDir));
        assertTrue(savedPath.getFileName().toString().endsWith(".tmp"));
        assertEquals("Valid document content", Files.readString(savedPath));

        // Cleanup
        uploadGuard.cleanupTempFile(savedPath);
        assertFalse(Files.exists(savedPath));
    }

    @Test
    @DisplayName("Empty or null upload throws IllegalArgumentException")
    void emptyFile_throwsException() {
        MockMultipartFile emptyFile = new MockMultipartFile(
                "document",
                "empty.txt",
                "text/plain",
                new byte[0]
        );

        assertThrows(IllegalArgumentException.class, () -> uploadGuard.saveToIsolatedTempFile(emptyFile));
        assertThrows(IllegalArgumentException.class, () -> uploadGuard.saveToIsolatedTempFile(null));
    }

    @Test
    @DisplayName("Upload exceeding maximum size limit throws IllegalArgumentException")
    void oversizedFile_throwsException() {
        byte[] oversizedData = new byte[(int) MAX_BYTES + 1];
        MockMultipartFile largeFile = new MockMultipartFile(
                "document",
                "large.bin",
                "application/octet-stream",
                oversizedData
        );

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> uploadGuard.saveToIsolatedTempFile(largeFile));
        assertTrue(ex.getMessage().contains("exceeds maximum allowable limit"));
    }

    @Test
    @DisplayName("Filename sanitization neutralizes directory traversal sequences")
    void sanitizeFilename_stripsPathTraversals() {
        assertEquals("passwd", uploadGuard.sanitizeFilename("../../etc/passwd"));
        assertEquals("evil.exe", uploadGuard.sanitizeFilename("..\\..\\Windows\\System32\\evil.exe"));
        assertEquals("report.pdf", uploadGuard.sanitizeFilename("/var/data/uploads/report.pdf"));
        assertEquals("document.docx", uploadGuard.sanitizeFilename("C:\\Users\\admin\\document.docx"));
        assertEquals("unnamed_document", uploadGuard.sanitizeFilename(""));
        assertEquals("unnamed_document", uploadGuard.sanitizeFilename("   "));
        assertEquals("unnamed_document", uploadGuard.sanitizeFilename("../.."));
    }

    @Test
    @DisplayName("Filename validation detects and rejects illegal traversal tokens")
    void validateFilename_detectsMaliciousInput() {
        assertThrows(IllegalArgumentException.class, () -> uploadGuard.validateFilename("../secret.txt"));
        assertThrows(IllegalArgumentException.class, () -> uploadGuard.validateFilename("dir/file.txt"));
        assertThrows(IllegalArgumentException.class, () -> uploadGuard.validateFilename("dir\\file.txt"));
        assertThrows(IllegalArgumentException.class, () -> uploadGuard.validateFilename("file\0.txt"));
        assertThrows(IllegalArgumentException.class, () -> uploadGuard.validateFilename(""));

        assertDoesNotThrow(() -> uploadGuard.validateFilename("legitimate-document_2026.pdf"));
    }

    @Test
    @DisplayName("Cleanup handles non-existent or null paths gracefully")
    void cleanup_handlesNullAndMissing() {
        assertDoesNotThrow(() -> uploadGuard.cleanupTempFile(null));
        assertDoesNotThrow(() -> uploadGuard.cleanupTempFile(tempDir.resolve("non-existent.tmp")));
    }

    @Test
    @DisplayName("Envelope validation enforces 512 KB cap and rejects oversized envelopes")
    void validateEnvelope_enforcesBounds() {
        MockMultipartFile validEnv = new MockMultipartFile("envelope", "valid.json", "application/json", "{}".getBytes());
        assertDoesNotThrow(() -> uploadGuard.validateEnvelope(validEnv));

        MockMultipartFile emptyEnv = new MockMultipartFile("envelope", "empty.json", "application/json", new byte[0]);
        assertThrows(IllegalArgumentException.class, () -> uploadGuard.validateEnvelope(emptyEnv));
        assertThrows(IllegalArgumentException.class, () -> uploadGuard.validateEnvelope(null));

        byte[] oversized = new byte[512 * 1024 + 1];
        MockMultipartFile largeEnv = new MockMultipartFile("envelope", "large.json", "application/json", oversized);
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> uploadGuard.validateEnvelope(largeEnv));
        assertTrue(ex.getMessage().contains("exceeds maximum allowable limit"));
    }
}
