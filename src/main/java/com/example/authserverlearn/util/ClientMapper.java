package com.example.authserverlearn.util;

import com.example.authserverlearn.entities.*;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class ClientMapper {

    public static RegisteredClient mapFromClient(Client client) {
        return RegisteredClient
                .withId(String.valueOf(client.getId()))
                .clientSecret(client.getSecret())
                .clientId(client.getClientId())
                .clientAuthenticationMethods(
                        c -> {
                            for (AuthenticationMethod authenticationMethod : client.getAuthentication()) {
                                ClientAuthenticationMethod clientAuthenticationMethod
                                        = new ClientAuthenticationMethod(authenticationMethod.getAuthentication());
                                c.add(clientAuthenticationMethod);
                            }
                        }
                )
                .authorizationGrantTypes(
                        c ->{
                            for (GrantType grantType : client.getGrantTypes()) {
                                AuthorizationGrantType authorizationGrantType = new AuthorizationGrantType(grantType.getGrantType());
                                c.add(authorizationGrantType);
                        }
                })
                .redirectUris(
                        c -> {
                            for (RedirectUrl redirectUrl : client.getRedirectUrls()) {
                                String redirectUri = redirectUrl.getUrl();
                                c.add(redirectUri);
                        }
                })
                .scopes(
                        c -> {
                            for (Scope scope : client.getScopes()) {
                                String scope1 = scope.getScope();
                                c.add(scope1);
                            }
                        })
                .build();
    }

    public static Client mapFromRegisteredClient(Client client, RegisteredClient registeredClient) {
        client.setClientId(registeredClient.getClientId());
        client.setSecret(registeredClient.getClientSecret());
        setClientAuthentications(client, registeredClient);
        setClientGrantTypes(client, registeredClient);
        setClientRedirectUrl(client, registeredClient);
        setClientScopes(client, registeredClient);

        return client;
    }

    private  static Set<AuthenticationMethod> setClientAuthentications(Client client, RegisteredClient registeredClient) {
        return registeredClient.getClientAuthenticationMethods().stream()
                .map(authMethod -> createAuthenticationMethod(client, authMethod))
                .collect(Collectors.toSet());
    }

    private static AuthenticationMethod createAuthenticationMethod(Client client, ClientAuthenticationMethod authMethod) {
        AuthenticationMethod authenticationMethod = new AuthenticationMethod();
        authenticationMethod.setAuthentication(authMethod.getValue());
        authenticationMethod.setClients(Collections.singleton(client));
        return authenticationMethod;
    }

    private static Set<Scope> setClientScopes(Client client, RegisteredClient registeredClient) {
        return registeredClient.getScopes().stream()
                .map(scope -> createScope(client, scope))
                .collect(Collectors.toSet());
    }

    private static Scope createScope(Client client, String scope) {
        Scope clientScope = new Scope();
        clientScope.setClients(Collections.singleton(client));
        clientScope.setScope(scope);
        return clientScope;
    }

    private static Set<GrantType> setClientGrantTypes(Client client, RegisteredClient registeredClient) {
        return registeredClient.getAuthorizationGrantTypes().stream()
                .map(authGrantType -> createGrantType(client, authGrantType))
                .collect(Collectors.toSet());
    }

    private static GrantType createGrantType(Client client, AuthorizationGrantType authGrantType) {
        GrantType grantType = new GrantType();
        grantType.setClients(Collections.singleton(client));
        grantType.setGrantType(authGrantType.getValue());
        return grantType;
    }

    private static Set<RedirectUrl> setClientRedirectUrl(Client client, RegisteredClient registeredClient) {
        return registeredClient.getRedirectUris().stream()
                .map(redirectUri -> createRedirectUrl(client, redirectUri))
                .collect(Collectors.toSet());
    }

    private static RedirectUrl createRedirectUrl(Client client, String redirectUri) {
        RedirectUrl redirectUrl = new RedirectUrl();
        redirectUrl.setClient(Collections.singleton(client));
        redirectUrl.setUrl(redirectUri);
        return redirectUrl;
    }
}
