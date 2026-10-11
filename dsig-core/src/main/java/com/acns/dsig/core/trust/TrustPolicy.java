package com.acns.dsig.core.trust;

import com.acns.dsig.core.api.ResultCode;
import com.acns.dsig.core.api.TrustLookup;
import com.acns.dsig.core.api.TrustStatus;

/**
 * Policy engine that maps signer key fingerprint trust state into authoritative result codes.
 *
 * <p>Default policy strictly rejects any key in {@link TrustStatus#RETIRED} or {@link TrustStatus#REVOKED} state,
 * mapping both to {@link ResultCode#REVOKED_OR_RETIRED_KEY}.</p>
 *
 * <p><b>Retired Key Semantics:</b> The system's {@link TrustLookup} interface currently provides only key status
 * and does not expose key retirement timestamps or lifecycle intervals. Therefore, the {@code allowRetiredKeys}
 * parameter functions strictly as an unconditional administrative override (e.g. for legacy verification modes)
 * and must not be mistaken for a signing-time-aware archival validation policy.</p>
 */
public class TrustPolicy {

    private final TrustLookup trustLookup;
    private final boolean allowRetiredKeys;

    /**
     * Creates a strict TrustPolicy that rejects REVOKED and RETIRED keys.
     */
    public TrustPolicy(TrustLookup trustLookup) {
        this(trustLookup, false);
    }

    /**
     * Creates a TrustPolicy with an explicit administrative override for RETIRED keys.
     *
     * @param trustLookup underlying trust repository
     * @param allowRetiredKeys unconditional administrative flag to permit RETIRED keys as VALID_TRUSTED
     */
    public TrustPolicy(TrustLookup trustLookup, boolean allowRetiredKeys) {
        this.trustLookup = trustLookup;
        this.allowRetiredKeys = allowRetiredKeys;
    }

    /**
     * Evaluates the trust status of a verified signature's key fingerprint.
     */
    public ResultCode evaluateTrust(String fingerprint) {
        if (trustLookup == null) {
            return ResultCode.VALID_UNTRUSTED_SIGNER;
        }

        TrustStatus status = trustLookup.getTrustStatus(fingerprint);
        return switch (status) {
            case TRUSTED -> ResultCode.VALID_TRUSTED;
            case REVOKED -> ResultCode.REVOKED_OR_RETIRED_KEY;
            case RETIRED -> allowRetiredKeys ? ResultCode.VALID_TRUSTED : ResultCode.REVOKED_OR_RETIRED_KEY;
            case UNTRUSTED, UNKNOWN -> ResultCode.VALID_UNTRUSTED_SIGNER;
        };
    }

    public TrustStatus getTrustStatus(String fingerprint) {
        if (trustLookup == null) {
            return TrustStatus.UNKNOWN;
        }
        return trustLookup.getTrustStatus(fingerprint);
    }

    public boolean isAllowRetiredKeys() {
        return allowRetiredKeys;
    }
}
