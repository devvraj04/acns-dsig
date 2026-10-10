package com.acns.dsig.server.service;

import com.acns.dsig.core.crypto.HashService;
import com.acns.dsig.core.crypto.SignatureService;
import com.acns.dsig.core.format.EnvelopeCodec;
import com.acns.dsig.core.keys.KeyStorage;
import com.acns.dsig.core.sign.SigningService;
import com.acns.dsig.server.persistence.AuditChainService;
import com.acns.dsig.server.persistence.KeyPairEntity;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

@Service
public class SigningAppService {

    private final KeyManagementService keyManagementService;
    private final AuditChainService auditChainService;
    private final SigningService coreSigningService;
    private final KeyStorage keyStorage;

    public SigningAppService(KeyManagementService keyManagementService, AuditChainService auditChainService) {
        this.keyManagementService = keyManagementService;
        this.auditChainService = auditChainService;
        this.coreSigningService = new SigningService(new HashService(), new SignatureService(), new EnvelopeCodec());
        this.keyStorage = new KeyStorage();
    }

    public SigningService.SignResult signDocument(
            Long userId,
            String keyId,
            char[] passphrase,
            String documentName,
            InputStream documentStream,
            String signerName
    ) throws Exception {
        KeyPairEntity keyEntity = keyManagementService.getKey(keyId)
                .orElseThrow(() -> new IllegalArgumentException("Key not found: " + keyId));

        if (!keyEntity.getOwnerId().equals(userId)) {
            throw new SecurityException("User does not own this signing key");
        }

        PrivateKey privateKey = null;
        try {
            privateKey = keyStorage.loadEncryptedPrivateKey(Path.of(keyEntity.getKeyFilePath()), passphrase);
            PublicKey publicKey = KeyStorage.parsePublicKeyFromPem(keyEntity.getPublicPem());

            SigningService.SignResult result = coreSigningService.sign(
                    documentStream,
                    documentName,
                    privateKey,
                    publicKey,
                    signerName
            );

            auditChainService.recordEvent(
                    userId,
                    "SIGN_DOCUMENT",
                    "Signed document " + documentName + " with key " + keyId + " (SHA256=" + result.documentHash() + ")"
            );

            return result;
        } finally {
            Arrays.fill(passphrase, '\0');
        }
    }
}
