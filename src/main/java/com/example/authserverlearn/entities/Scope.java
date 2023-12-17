package com.example.authserverlearn.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

@Entity
@Table(schema = "oauth_spilca", name = "scopes")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Scope {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String scope;

    @ManyToMany(mappedBy = "scopes")
    private Set<Client> clients;
}
