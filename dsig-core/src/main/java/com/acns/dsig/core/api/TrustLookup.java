package com.acns.dsig.core.api;

import java.util.Optional;

/**
 * Common contract for resolving trust status and metadata for a public key fingerprint.
 * Implemented by FileTrustStore in CLI and TrustStoreService in Spring Boot server.
 */
public interface TrustLookup {

    /**
     * Resolves the trust status of the given public key fingerprint.
     *
     * @param fingerprint normalized SHA-256 SPKI fingerprint
     * @return the TrustStatus for this fingerprint
     */
    TrustStatus getTrustStatus(String fingerprint);

    /**
     * Retrieves optional label or human-readable identifier associated with the trusted fingerprint.
     *
     * @param fingerprint normalized SHA-256 SPKI fingerprint
     * @return optional signer label
     */
    Optional<String> getSignerLabel(String fingerprint);
}
