package com.jinyeong.springsecurityjwt.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "user")
@Setter
@Getter
public class UserEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    // Unique Column 옵션
    @Column(unique = true)
    private String username;

    private String password;

    private String role;
}
