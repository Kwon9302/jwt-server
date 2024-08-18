package com.cos.jwt.repository;

import com.cos.jwt.model.User2;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User2, Long> {
    User2 findByUsername(String username);

}
