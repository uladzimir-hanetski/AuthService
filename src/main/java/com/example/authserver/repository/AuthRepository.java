package com.example.authserver.repository;

import com.example.authserver.entity.UserCredentials;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuthRepository extends JpaRepository<UserCredentials, UUID> {

    boolean existsByLogin(String login);

    Optional<UserCredentials> findByLogin(String login);
}
