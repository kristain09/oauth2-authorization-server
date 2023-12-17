package com.example.authserverlearn.entities;

import jakarta.persistence.*;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Set;

@Getter
@Setter
@Entity
@Table(name = "clients", schema = "oauth_spilca")
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    @Column(name = "client_id", nullable = false)
    private String clientId;

    @Column(name = "secret", nullable = false)
    private String secret;

    @ManyToMany
    @JoinTable(
            name = "client_authentication_method",
            joinColumns = @JoinColumn(name = "client_id"),
            inverseJoinColumns = @JoinColumn(name = "authentication_method_id")
    )
    private Set<AuthenticationMethod> authentication;

    @ManyToMany
    @JoinTable(
            name = "client_redirect_urls",
            joinColumns = @JoinColumn(name = "client_id"),
            inverseJoinColumns = @JoinColumn(name = "redirect_url_id")
    )
    private Set<RedirectUrl> redirectUrls;

    @ManyToMany(mappedBy = "client")
    @JoinTable(
            name = "client_scopes",
            joinColumns = @JoinColumn(name = "client_id"),
            inverseJoinColumns = @JoinColumn(name = "scope_id")
    )
    private Set<Scope> scopes;

    @ManyToMany
    @JoinTable(
            name = "client_grant_types",
            joinColumns = @JoinColumn(name = "client_id"),
            inverseJoinColumns = @JoinColumn(name = "grant_type_id")
    )
    private Set<GrantType> grantTypes;
}
