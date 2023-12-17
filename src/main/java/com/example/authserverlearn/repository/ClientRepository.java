package com.example.authserverlearn.repository;

import com.example.authserverlearn.entities.Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface ClientRepository extends JpaRepository<Client, Integer> {

    public Optional<Client> findByClientId(String clientId);
}
