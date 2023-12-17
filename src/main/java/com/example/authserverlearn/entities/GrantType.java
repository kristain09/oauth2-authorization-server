package com.example.authserverlearn.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

@Entity
@Table(schema = "oauth_spilca", name = "grant_types")
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class GrantType {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @Column(name = "grant_type", nullable = false)
    private String grantType;

    @ManyToMany(mappedBy = "grantTypes")
    private Set<Client> clients;
}
