package com.acns.dsig.server.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

/**
 * File upload guard ensuring size bounds, isolated temporary storage, and secure cleanup.
 */
@Component
public class UploadGuard {

    private final Path tempUploadDir;
    private final long maxFileSizeBytes;

    public UploadGuard(
            @Value("${dsig.upload.tmp-dir:runtime/uploads-tmp}") String tmpDir,
            @Value("${dsig.upload.max-bytes:52428800}") long maxFileSizeBytes // 50MB
    ) throws IOException {
        this.tempUploadDir = Path.of(tmpDir);
        this.maxFileSizeBytes = maxFileSizeBytes;
        if (!Files.exists(tempUploadDir)) {
            Files.createDirectories(tempUploadDir);
        }
    }

    public Path saveToIsolatedTempFile(MultipartFile file) throws IOException {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Upload file is empty or missing");
        }
        if (file.getSize() > maxFileSizeBytes) {
            throw new IllegalArgumentException("File size (" + file.getSize() + " bytes) exceeds maximum allowable limit");
        }

        String safeFileName = UUID.randomUUID() + ".tmp";
        Path targetPath = tempUploadDir.resolve(safeFileName);
        file.transferTo(targetPath);
        return targetPath;
    }

    public void cleanupTempFile(Path tempFilePath) {
        if (tempFilePath != null) {
            try {
                Files.deleteIfExists(tempFilePath);
            } catch (IOException ignored) {}
        }
    }
}
