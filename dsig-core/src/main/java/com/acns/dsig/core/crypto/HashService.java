package com.acns.dsig.core.crypto;

import com.acns.dsig.core.api.HashResult;
import com.acns.dsig.core.error.CryptoException;
import com.acns.dsig.core.error.DocumentReadException;
import com.acns.dsig.core.error.EmptyDocumentException;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Objects;

/**
 * High-performance streaming document hashing service using SHA-256.
 *
 * Owned by: Devraj Sundrani (Member 2)
 * Work Package: Document Processing & SHA-256 Hashing
 *
 * Key guarantees:
 * - Constant-memory footprint: Uses a fixed-size buffer regardless of document size.
 * - Simultaneous size calculation: Counts exact streamed bytes during digest update.
 * - Format agnostic: Operates strictly on raw file bytes; supports any MIME or binary format.
 * - Strict input validation: Rejects 0-byte (empty) files as required by Section 8.3.
 * - Robust error handling: Distinguishes between empty files and underlying I/O failures.
 */
public class HashService {

    private final int bufferSize;

    public HashService() {
        this(CryptoConfig.STREAM_BUFFER_SIZE); // Default 64 KB
    }

    public HashService(int bufferSize) {
        if (bufferSize <= 0) {
            throw new IllegalArgumentException("Buffer size must be greater than 0");
        }
        this.bufferSize = bufferSize;
    }

    public int getBufferSize() {
        return bufferSize;
    }

    /**
     * Streams an arbitrary InputStream through SHA-256 and calculates document size.
     *
     * @param in the InputStream containing document bytes
     * @return HashResult containing raw, hex, base64 digests and byte count
     * @throws EmptyDocumentException if the stream contains 0 bytes
     * @throws DocumentReadException if an I/O error occurs while reading
     */
    public HashResult hashStream(InputStream in) {
        if (in == null) {
            throw new IllegalArgumentException("InputStream cannot be null");
        }

        MessageDigest digest = createMessageDigest();
        byte[] buffer = new byte[bufferSize];
        long totalBytes = 0;
        int bytesRead;

        try {
            while ((bytesRead = in.read(buffer)) != -1) {
                if (bytesRead > 0) {
                    digest.update(buffer, 0, bytesRead);
                    totalBytes += bytesRead;
                }
            }
        } catch (IOException e) {
            throw new DocumentReadException("I/O error while streaming document for hashing: " + e.getMessage(), e);
        }

        if (totalBytes == 0) {
            throw new EmptyDocumentException("Document is empty (0 bytes). Empty documents cannot be signed or verified.");
        }

        byte[] rawDigest = digest.digest();
        String hexDigest = HexFormat.of().formatHex(rawDigest).toLowerCase();
        String base64Digest = Base64.getEncoder().encodeToString(rawDigest);

        return new HashResult(rawDigest, hexDigest, base64Digest, totalBytes, CryptoConfig.HASH_ALGORITHM);
    }

    /**
     * Hashes a file on disk by opening a buffered stream.
     * Works for arbitrary file types (PDF, Office docs, images, binaries, source code).
     *
     * @param filePath Path to the target file
     * @return HashResult containing raw, hex, base64 digests and byte count
     */
    public HashResult hashFile(Path filePath) {
        Objects.requireNonNull(filePath, "filePath cannot be null");
        if (!Files.exists(filePath)) {
            throw new DocumentReadException("Target document file does not exist: " + filePath.toAbsolutePath());
        }
        if (Files.isDirectory(filePath)) {
            throw new DocumentReadException("Target path is a directory, not a document: " + filePath.toAbsolutePath());
        }

        try (InputStream in = new BufferedInputStream(Files.newInputStream(filePath), bufferSize)) {
            return hashStream(in);
        } catch (IOException e) {
            throw new DocumentReadException("Failed to open or read file: " + filePath + " (" + e.getMessage() + ")", e);
        }
    }

    /**
     * Hashes an in-memory byte array directly.
     *
     * @param data document bytes
     * @return HashResult containing raw, hex, base64 digests and byte count
     */
    public HashResult hashBytes(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }
        if (data.length == 0) {
            throw new EmptyDocumentException("Document byte array is empty (0 bytes).");
        }

        MessageDigest digest = createMessageDigest();
        digest.update(data);
        byte[] rawDigest = digest.digest();

        String hexDigest = HexFormat.of().formatHex(rawDigest).toLowerCase();
        String base64Digest = Base64.getEncoder().encodeToString(rawDigest);

        return new HashResult(rawDigest, hexDigest, base64Digest, data.length, CryptoConfig.HASH_ALGORITHM);
    }

    /**
     * Constant-time comparison between two raw hash byte arrays.
     */
    public boolean verifyHash(byte[] expectedHash, byte[] actualHash) {
        return ConstantTime.equals(expectedHash, actualHash);
    }

    /**
     * Constant-time comparison between two hex-encoded hash strings.
     */
    public boolean verifyHexHash(String expectedHex, String actualHex) {
        return ConstantTime.equals(expectedHex, actualHex);
    }

    private MessageDigest createMessageDigest() {
        try {
            return MessageDigest.getInstance(CryptoConfig.HASH_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Cryptographic algorithm unavailable: " + CryptoConfig.HASH_ALGORITHM, e);
        }
    }
}
