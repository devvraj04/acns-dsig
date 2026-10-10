package com.acns.dsig.core.crypto;

import com.acns.dsig.core.api.HashResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Performance benchmarking suite for HashService streaming operations.
 *
 * Owned by: Devraj Sundrani (Member 2)
 * Work Package: Document Processing & SHA-256 Hashing
 *
 * Evaluates latency and throughput across 1 KB, 1 MB, and 25 MB streams.
 */
public class HashBenchmarkTest {

    private HashService hashService;

    @BeforeEach
    void setUp() {
        hashService = new HashService();
    }

    @Test
    @DisplayName("Benchmark 1 KB file hashing")
    void benchmark1Kb() {
        byte[] data = new byte[1024];
        new Random(101).nextBytes(data);

        // Warmup
        for (int i = 0; i < 1000; i++) {
            hashService.hashStream(new ByteArrayInputStream(data));
        }

        // Measure
        int iterations = 10_000;
        long start = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            hashService.hashStream(new ByteArrayInputStream(data));
        }
        long durationNs = System.nanoTime() - start;

        double ms = durationNs / 1_000_000.0;
        double avgUsPerOp = (durationNs / (double) iterations) / 1000.0;
        double mbTotal = (iterations * 1024.0) / (1024 * 1024);
        double throughputMBps = mbTotal / (durationNs / 1_000_000_000.0);

        System.out.printf("[BENCHMARK - 1 KB] %d ops in %.2f ms | Avg: %.2f µs/op | Throughput: %.2f MB/s%n",
                iterations, ms, avgUsPerOp, throughputMBps);
    }

    @Test
    @DisplayName("Benchmark 1 MB file hashing")
    void benchmark1Mb() {
        byte[] data = new byte[1024 * 1024]; // 1 MB
        new Random(202).nextBytes(data);

        // Warmup
        for (int i = 0; i < 10; i++) {
            hashService.hashStream(new ByteArrayInputStream(data));
        }

        // Measure
        int iterations = 100;
        long start = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            hashService.hashStream(new ByteArrayInputStream(data));
        }
        long durationNs = System.nanoTime() - start;

        double ms = durationNs / 1_000_000.0;
        double avgMsPerOp = ms / iterations;
        double mbTotal = (iterations * (1024.0 * 1024.0)) / (1024 * 1024);
        double throughputMBps = mbTotal / (durationNs / 1_000_000_000.0);

        System.out.printf("[BENCHMARK - 1 MB] %d ops in %.2f ms | Avg: %.2f ms/op | Throughput: %.2f MB/s%n",
                iterations, ms, avgMsPerOp, throughputMBps);
    }

    @Test
    @DisplayName("Benchmark 25 MB virtual stream hashing (constant memory footprint)")
    void benchmark25MbStream() {
        final long totalBytes = 25L * 1024 * 1024; // 25 MB

        // Generator stream that produces 25 MB without allocating 25 MB in RAM
        InputStream virtualStream = new InputStream() {
            private long remaining = totalBytes;

            @Override
            public int read() {
                if (remaining <= 0) return -1;
                remaining--;
                return (int) (remaining & 0xFF);
            }

            @Override
            public int read(byte[] b, int off, int len) {
                if (remaining <= 0) return -1;
                int toRead = (int) Math.min(len, remaining);
                for (int i = 0; i < toRead; i++) {
                    b[off + i] = (byte) ((remaining - i) & 0xFF);
                }
                remaining -= toRead;
                return toRead;
            }
        };

        long start = System.nanoTime();
        HashResult result = hashService.hashStream(virtualStream);
        long durationNs = System.nanoTime() - start;

        double ms = durationNs / 1_000_000.0;
        double throughputMBps = 25.0 / (durationNs / 1_000_000_000.0);

        assertNotNull(result);
        assertEquals(totalBytes, result.byteCount());

        System.out.printf("[BENCHMARK - 25 MB Virtual Stream] Hashed in %.2f ms | Throughput: %.2f MB/s%n",
                ms, throughputMBps);
    }
}
