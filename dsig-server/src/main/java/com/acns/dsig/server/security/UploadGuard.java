package com.acns.dsig.server.security;

import com.acns.dsig.core.format.FormatLimits;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.UUID;

/**
 * File upload guard ensuring size bounds, isolated temporary storage,
 * path traversal defense, and secure lifecycle cleanup.
 */
@Component
public class UploadGuard {

    private static final Logger log = LoggerFactory.getLogger(UploadGuard.class);

    private final Path tempUploadDir;
    private final long maxFileSizeBytes;

    public UploadGuard(
            @Value("${dsig.upload.tmp-dir:runtime/uploads-tmp}") String tmpDir,
            @Value("${dsig.upload.max-bytes:52428800}") long maxFileSizeBytes // 50MB default
    ) throws IOException {
        this.tempUploadDir = Path.of(tmpDir).toAbsolutePath().normalize();
        this.maxFileSizeBytes = maxFileSizeBytes;
        if (!Files.exists(this.tempUploadDir)) {
            Files.createDirectories(this.tempUploadDir);
        }
    }

    /**
     * Validates that an envelope upload is present, non-empty, and does not exceed the
     * authoritative maximum envelope JSON size limit (512 KB) before loading into memory.
     */
    public void validateEnvelope(MultipartFile envelopeFile) {
        if (envelopeFile == null || envelopeFile.isEmpty()) {
            throw new IllegalArgumentException("Signature envelope file is empty or missing");
        }
        if (envelopeFile.getSize() > FormatLimits.MAX_ENVELOPE_JSON_BYTES) {
            throw new IllegalArgumentException(String.format(
                    "Envelope file size (%d bytes) exceeds maximum allowable limit of %d bytes",
                    envelopeFile.getSize(), FormatLimits.MAX_ENVELOPE_JSON_BYTES));
        }
    }

    /**
     * Saves uploaded multipart file to an isolated, uniquely named temporary file.
     * Prevents path traversal, enforces size caps, and restricts storage to the isolated temp directory.
     */
    public Path saveToIsolatedTempFile(MultipartFile file) throws IOException {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Upload file is empty or missing");
        }
        if (file.getSize() > maxFileSizeBytes) {
            throw new IllegalArgumentException(String.format(
                    "File size (%d bytes) exceeds maximum allowable limit of %d bytes",
                    file.getSize(), maxFileSizeBytes));
        }

        String safeFileName = UUID.randomUUID() + ".tmp";
        Path targetPath = tempUploadDir.resolve(safeFileName).normalize().toAbsolutePath();

        // Security check: ensure resolved path does not escape the upload directory
        if (!targetPath.startsWith(tempUploadDir)) {
            throw new SecurityException("Target path outside isolated upload directory");
        }

        file.transferTo(targetPath);
        return targetPath;
    }

    /**
     * Sanitizes an uploaded filename to prevent directory traversal attacks and invalid path characters.
     * Strips directory components and illegal filesystem characters.
     */
    public String sanitizeFilename(String filename) {
        if (filename == null || filename.isBlank()) {
            return "unnamed_document";
        }

        // Strip path prefixes (both UNIX and Windows style)
        String baseName = filename.replace('\\', '/');
        int lastSlash = baseName.lastIndexOf('/');
        if (lastSlash != -1) {
            baseName = baseName.substring(lastSlash + 1);
        }

        // Remove path traversal tokens and dangerous characters
        baseName = baseName.replace("..", "").replaceAll("[\\p{Cntrl}\\\\/:*?\"<>|\0]", "_").trim();

        if (baseName.isBlank() || baseName.equals(".") || baseName.equals("..")) {
            return "unnamed_document";
        }

        // Limit length to 255 chars
        if (baseName.length() > 255) {
            baseName = baseName.substring(0, 255);
        }

        return baseName;
    }

    /**
     * Validates that a filename does not contain path traversal sequences or forbidden characters.
     */
    public void validateFilename(String filename) {
        if (filename == null || filename.isBlank()) {
            throw new IllegalArgumentException("Filename cannot be empty");
        }
        if (filename.contains("..") || filename.contains("/") || filename.contains("\\") || filename.contains("\0")) {
            throw new IllegalArgumentException("Path traversal or illegal characters detected in filename");
        }
    }

    /**
     * Deletes a temporary file safely, confirming it resides inside the designated upload directory.
     */
    public void cleanupTempFile(Path tempFilePath) {
        if (tempFilePath != null) {
            try {
                Path normalized = tempFilePath.toAbsolutePath().normalize();
                if (normalized.startsWith(tempUploadDir)) {
                    Files.deleteIfExists(normalized);
                } else {
                    log.warn("Refusing to delete file outside upload directory: {}", tempFilePath);
                }
            } catch (IOException e) {
                log.warn("Failed to delete temporary upload file {}: {}", tempFilePath, e.getMessage());
            }
        }
    }

    /**
     * Removes orphaned temporary upload files older than the specified age in milliseconds.
     */
    public int cleanupOrphanedFiles(long maxAgeMillis) {
        int deletedCount = 0;
        Instant cutoff = Instant.now().minusMillis(maxAgeMillis);

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(tempUploadDir, "*.tmp")) {
            for (Path entry : stream) {
                try {
                    FileTime lastModified = Files.getLastModifiedTime(entry);
                    if (lastModified.toInstant().isBefore(cutoff)) {
                        Files.deleteIfExists(entry);
                        deletedCount++;
                    }
                } catch (IOException ignored) {}
            }
        } catch (IOException e) {
            log.warn("Error scanning temp upload directory for cleanup: {}", e.getMessage());
        }

        return deletedCount;
    }

    public Path getTempUploadDir() {
        return tempUploadDir;
    }

    public long getMaxFileSizeBytes() {
        return maxFileSizeBytes;
    }
}
