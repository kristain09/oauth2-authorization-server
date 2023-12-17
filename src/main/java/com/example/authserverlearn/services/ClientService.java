package com.example.authserverlearn.services;

import com.example.authserverlearn.entities.*;
import com.example.authserverlearn.repository.ClientRepository;
import com.example.authserverlearn.util.ClientMapper;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
@AllArgsConstructor
@Transactional
public class ClientService implements RegisteredClientRepository {

    private final ClientRepository clientRepository;

    @Override
    @Transactional
    public void save(RegisteredClient registeredClient) {
        Client client = ClientMapper.mapFromRegisteredClient(new Client(), registeredClient);

        clientRepository.save(client);
    }

    @Override
    public RegisteredClient findById(String id) {
        Optional<Client> client = clientRepository.findById(Integer.parseInt(id));

        return client.map(ClientMapper::mapFromClient)
                .orElseThrow(() -> new RuntimeException(":("));
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Optional<Client> client = clientRepository.findByClientId(clientId);

        return client.map(ClientMapper::mapFromClient)
                .orElseThrow(() -> new RuntimeException(":("));
    }
}
