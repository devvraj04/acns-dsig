package com.acns.dsig.server.persistence;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface KeyPairRepository extends JpaRepository<KeyPairEntity, String> {
    List<KeyPairEntity> findByOwnerId(Long ownerId);
}
