package com.sentinelops.service;

import com.sentinelops.entity.Client;
import com.sentinelops.entity.Role;
import com.sentinelops.entity.User;
import com.sentinelops.exception.NotFoundException;
import com.sentinelops.repository.ClientRepository;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
public class ClientService {

    private final ClientRepository clients;
    private final AccessService access;
    private final AuditService audit;

    public ClientService(ClientRepository clients, AccessService access, AuditService audit) {
        this.clients = clients;
        this.access = access;
        this.audit = audit;
    }

    @Transactional(readOnly = true)
    public List<Client> list() {
        User u = access.currentUser();
        if (u.getRole() == Role.CLIENT) {
            return u.getClientId() == null ? List.of() : clients.findById(u.getClientId()).map(List::of).orElse(List.of());
        }
        return clients.findAll();
    }

    @Transactional(readOnly = true)
    public Client get(String id) {
        User u = access.currentUser();
        if (u.getRole() == Role.CLIENT && !id.equals(u.getClientId())) {
            throw new AccessDeniedException("Access denied");
        }
        return clients.findById(id).orElseThrow(() -> new NotFoundException("Client not found"));
    }

    @PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
    @Transactional
    public Client create(String name, String contact, String tier, String compliance, String actor) {
        Client c = new Client(UUID.randomUUID().toString(), name.trim(), contact.trim(), tier, compliance);
        clients.save(c);
        audit.record(actor, "client.created", "Client", c.getId(), "name=" + c.getName());
        return c;
    }
}
