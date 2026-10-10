package com.acns.dsig.core.crypto;

import com.acns.dsig.core.api.HashResult;
import com.acns.dsig.core.error.DocumentReadException;
import com.acns.dsig.core.error.EmptyDocumentException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Exhaustive unit tests and NIST Known-Answer Tests (KAT) for HashService and ConstantTime.
 *
 * Owned by: Devraj Sundrani (Member 2)
 * Work Package: Document Processing & SHA-256 Hashing
 */
public class HashServiceTest {

    private HashService hashService;

    @BeforeEach
    void setUp() {
        hashService = new HashService();
    }

    @Nested
    @DisplayName("NIST FIPS 180-4 Known-Answer Tests (KAT)")
    class NistKnownAnswerTests {

        @Test
        @DisplayName("NIST Vector 1: 'abc'")
        void testNistVector1() {
            String input = "abc";
            String expectedHex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

            HashResult result = hashService.hashBytes(input.getBytes(StandardCharsets.UTF_8));

            assertEquals(expectedHex, result.hexDigest());
            assertEquals(3, result.byteCount());
            assertEquals(CryptoConfig.HASH_ALGORITHM, result.algorithm());
            assertTrue(ConstantTime.equalsHex(expectedHex, result.hexDigest()));
        }

        @Test
        @DisplayName("NIST Vector 2: 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq' (56 bytes)")
        void testNistVector2() {
            String input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
            String expectedHex = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

            HashResult result = hashService.hashBytes(input.getBytes(StandardCharsets.UTF_8));

            assertEquals(expectedHex, result.hexDigest());
            assertEquals(56, result.byteCount());
            assertTrue(ConstantTime.equalsHex(expectedHex, result.hexDigest()));
        }

        @Test
        @DisplayName("NIST Vector 3: 1,000,000 repetitions of 'a' streamed in chunks")
        void testNistVector3OneMillionAs() {
            // FIPS 180-4 specifies SHA-256("a" * 1,000,000) =
            // cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0
            String expectedHex = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

            InputStream repeatingStream = new InputStream() {
                private long remaining = 1_000_000L;

                @Override
                public int read() {
                    if (remaining > 0) {
                        remaining--;
                        return 'a';
                    }
                    return -1;
                }

                @Override
                public int read(byte[] b, int off, int len) {
                    if (remaining <= 0) return -1;
                    int toRead = (int) Math.min(len, remaining);
                    Arrays.fill(b, off, off + toRead, (byte) 'a');
                    remaining -= toRead;
                    return toRead;
                }
            };

            HashResult result = hashService.hashStream(repeatingStream);

            assertEquals(expectedHex, result.hexDigest());
            assertEquals(1_000_000L, result.byteCount());
            assertTrue(ConstantTime.equalsHex(expectedHex, result.hexDigest()));
        }
    }

    @Nested
    @DisplayName("Streaming & Fixed Buffer Integrity")
    class StreamingBufferTests {

        @Test
        @DisplayName("Streaming multi-buffer data (150 KB) matches full byte hash")
        void testMultiBufferStreaming() {
            byte[] largeData = new byte[150 * 1024]; // 150 KB (larger than 64 KB buffer)
            new Random(42).nextBytes(largeData);

            HashResult bytesResult = hashService.hashBytes(largeData);
            HashResult streamResult = hashService.hashStream(new ByteArrayInputStream(largeData));

            assertEquals(bytesResult.hexDigest(), streamResult.hexDigest());
            assertEquals(150 * 1024, streamResult.byteCount());
            assertTrue(ConstantTime.equals(bytesResult.rawDigest(), streamResult.rawDigest()));
        }

        @Test
        @DisplayName("Custom small buffer size (16 bytes) produces identical digest")
        void testCustomSmallBuffer() {
            HashService smallBufferService = new HashService(16);
            assertEquals(16, smallBufferService.getBufferSize());

            byte[] data = "Testing streaming with tiny buffer chunks".getBytes(StandardCharsets.UTF_8);
            HashResult standardRes = hashService.hashBytes(data);
            HashResult smallRes = smallBufferService.hashStream(new ByteArrayInputStream(data));

            assertEquals(standardRes.hexDigest(), smallRes.hexDigest());
            assertEquals(data.length, smallRes.byteCount());
        }

        @Test
        @DisplayName("Arbitrary binary data (PDF magic header, null bytes) processed correctly")
        void testArbitraryBinaryData() {
            byte[] binary = new byte[] { '%', 'P', 'D', 'F', '-', '1', '.', '7', 0x00, (byte) 0xFF, 0x1A, 0x0A };
            HashResult result = hashService.hashBytes(binary);

            assertNotNull(result);
            assertEquals(binary.length, result.byteCount());
            assertEquals(32, result.rawDigest().length);
        }
    }

    @Nested
    @DisplayName("Input Validation & Exception Handling")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Rejects empty byte array with EmptyDocumentException")
        void testEmptyByteArrayRejected() {
            assertThrows(EmptyDocumentException.class, () -> hashService.hashBytes(new byte[0]));
        }

        @Test
        @DisplayName("Rejects empty stream (0 bytes) with EmptyDocumentException")
        void testEmptyStreamRejected() {
            InputStream emptyStream = new ByteArrayInputStream(new byte[0]);
            assertThrows(EmptyDocumentException.class, () -> hashService.hashStream(emptyStream));
        }

        @Test
        @DisplayName("Rejects null input with IllegalArgumentException")
        void testNullInputRejected() {
            assertThrows(IllegalArgumentException.class, () -> hashService.hashStream(null));
            assertThrows(IllegalArgumentException.class, () -> hashService.hashBytes(null));
        }

        @Test
        @DisplayName("Wraps stream I/O failure into DocumentReadException")
        void testStreamReadFailure() {
            InputStream faultyStream = new InputStream() {
                @Override
                public int read() throws IOException {
                    throw new IOException("Simulated disk read error");
                }
            };

            assertThrows(DocumentReadException.class, () -> hashService.hashStream(faultyStream));
        }

        @Test
        @DisplayName("Rejects directory path as document input")
        void testDirectoryPathRejected(@TempDir Path tempDir) {
            assertThrows(DocumentReadException.class, () -> hashService.hashFile(tempDir));
        }

        @Test
        @DisplayName("Rejects non-existent file path")
        void testNonExistentFileRejected() {
            Path nonExistent = Path.of("does_not_exist_file_99999.pdf");
            assertThrows(DocumentReadException.class, () -> hashService.hashFile(nonExistent));
        }
    }

    @Nested
    @DisplayName("Disk File Hashing")
    class DiskFileHashingTests {

        @Test
        @DisplayName("hashFile correctly hashes on-disk document file", @TempDir Path tempDir) throws IOException {
            Path testFile = tempDir.resolve("sample.pdf");
            byte[] content = "PDF Document Mock Content for Hashing".getBytes(StandardCharsets.UTF_8);
            Files.write(testFile, content);

            HashResult result = hashService.hashFile(testFile);

            assertNotNull(result);
            assertEquals(content.length, result.byteCount());
            assertEquals(hashService.hashBytes(content).hexDigest(), result.hexDigest());
        }
    }

    @Nested
    @DisplayName("Constant-Time Comparison Tests")
    class ConstantTimeComparisonTests {

        @Test
        @DisplayName("ConstantTime validates byte array and hex equality")
        void testConstantTimeEvaluation() {
            byte[] a = "digest_value_1".getBytes(StandardCharsets.UTF_8);
            byte[] b = "digest_value_1".getBytes(StandardCharsets.UTF_8);
            byte[] c = "digest_value_2".getBytes(StandardCharsets.UTF_8);

            assertTrue(ConstantTime.equals(a, b));
            assertFalse(ConstantTime.equals(a, c));
            assertTrue(ConstantTime.equals((byte[]) null, (byte[]) null));
            assertFalse(ConstantTime.equals(a, null));

            assertTrue(ConstantTime.equalsHex("BA7816BF", "ba7816bf"));
            assertFalse(ConstantTime.equalsHex("ba7816bf", "248d6a61"));
        }
    }
}
