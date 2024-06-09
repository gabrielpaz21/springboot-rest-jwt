package net.openwebinars.springboot.restjwt.user.repo;

import net.openwebinars.springboot.restjwt.user.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findFirstByUsername(String username);

}
