package com.acns.dsig.core.trust;

import com.acns.dsig.core.api.ResultCode;
import com.acns.dsig.core.api.TrustLookup;
import com.acns.dsig.core.api.TrustStatus;

/**
 * Policy engine that maps signer key fingerprint trust state into authoritative result codes.
 */
public class TrustPolicy {

    private final TrustLookup trustLookup;

    public TrustPolicy(TrustLookup trustLookup) {
        this.trustLookup = trustLookup;
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
            case REVOKED, RETIRED -> ResultCode.REVOKED_OR_RETIRED_KEY;
            case UNTRUSTED, UNKNOWN -> ResultCode.VALID_UNTRUSTED_SIGNER;
        };
    }

    public TrustStatus getTrustStatus(String fingerprint) {
        if (trustLookup == null) {
            return TrustStatus.UNKNOWN;
        }
        return trustLookup.getTrustStatus(fingerprint);
    }
}
