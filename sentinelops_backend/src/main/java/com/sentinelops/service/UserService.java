package com.sentinelops.service;

import com.sentinelops.entity.Role;
import com.sentinelops.entity.User;
import com.sentinelops.exception.NotFoundException;
import com.sentinelops.repository.ClientRepository;
import com.sentinelops.repository.UserRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Service
public class UserService {

    private final UserRepository users;
    private final ClientRepository clients;
    private final PasswordEncoder encoder;
    private final AuditService audit;

    public UserService(UserRepository users, ClientRepository clients, PasswordEncoder encoder, AuditService audit) {
        this.users = users;
        this.clients = clients;
        this.encoder = encoder;
        this.audit = audit;
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Transactional(readOnly = true)
    public List<User> list() {
        return users.findAll();
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public User create(String name, String email, String password, Role role, String clientId, String actor) {
        String mail = email.trim().toLowerCase(Locale.ROOT);
        if (users.findByEmail(mail).isPresent()) {
            throw new IllegalStateException("A user with this email already exists.");
        }
        if (password == null || password.length() < 10) {
            throw new IllegalArgumentException("The password must be at least 10 characters.");
        }
        if (role == Role.CLIENT) {
            if (clientId == null) throw new IllegalArgumentException("A CLIENT user must be linked to a client.");
            clients.findById(clientId).orElseThrow(() -> new NotFoundException("Client not found"));
        }
        User u = new User(UUID.randomUUID().toString(), name.trim(), mail, encoder.encode(password), role, null);
        if (role == Role.CLIENT) u.setClientId(clientId);
        users.save(u);
        audit.record(actor, "user.created", "User", u.getId(), "email=" + mail + " role=" + role);
        return u;
    }
}
