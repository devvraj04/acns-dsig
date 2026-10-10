package com.acns.dsig.server.service;

import com.acns.dsig.core.keys.KeyService;
import com.acns.dsig.core.keys.KeyStorage;
import com.acns.dsig.server.persistence.KeyPairEntity;
import com.acns.dsig.server.persistence.KeyPairRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

@Service
public class KeyManagementService {

    private final KeyPairRepository keyPairRepository;
    private final Path keysDirectory;

    public KeyManagementService(
            KeyPairRepository keyPairRepository,
            @Value("${dsig.keys.dir:runtime/keys}") String keysDirPath
    ) {
        this.keyPairRepository = keyPairRepository;
        this.keysDirectory = Path.of(keysDirPath);
    }

    @Transactional
    public KeyPairEntity generateAndStoreKey(Long ownerId, String label, char[] passphrase) throws IOException {
        if (!Files.exists(keysDirectory)) {
            Files.createDirectories(keysDirectory);
        }

        KeyService keyService = new KeyService();
        KeyService.GeneratedKeyPair generated = keyService.generateKeyPair();

        Path keyFilePath = keysDirectory.resolve(generated.fingerprint() + ".pk8");
        KeyStorage storage = new KeyStorage();
        storage.saveEncryptedPrivateKey(generated.keyPair().getPrivate(), passphrase, keyFilePath);

        String publicPem = KeyStorage.exportPublicKeyToPem(generated.keyPair().getPublic());

        KeyPairEntity entity = new KeyPairEntity();
        entity.setKeyId(generated.fingerprint());
        entity.setOwnerId(ownerId);
        entity.setLabel(label);
        entity.setPublicPem(publicPem);
        entity.setKeyFilePath(keyFilePath.toString());
        entity.setStatus("ACTIVE");

        return keyPairRepository.save(entity);
    }

    @Transactional(readOnly = true)
    public List<KeyPairEntity> getKeysForUser(Long ownerId) {
        return keyPairRepository.findByOwnerId(ownerId);
    }

    @Transactional(readOnly = true)
    public Optional<KeyPairEntity> getKey(String keyId) {
        return keyPairRepository.findById(keyId);
    }
}
