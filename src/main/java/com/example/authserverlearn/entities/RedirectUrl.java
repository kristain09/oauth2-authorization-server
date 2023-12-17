package com.example.authserverlearn.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

@Entity
@Getter
@Setter
@Table(name = "redirect_urls", schema = "oauth_spilca")
@AllArgsConstructor
@NoArgsConstructor
public class RedirectUrl {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String url;

    @ManyToMany(mappedBy = "redirectUrls")
    private Set<Client> client;
}
