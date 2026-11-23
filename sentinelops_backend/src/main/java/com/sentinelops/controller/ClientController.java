package com.sentinelops.controller;

import com.sentinelops.dto.ClientDtos.ClientRequest;
import com.sentinelops.dto.ClientDtos.ClientView;
import com.sentinelops.service.ClientService;
import com.sentinelops.util.CurrentUser;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/clients")
public class ClientController {

    private final ClientService clients;

    public ClientController(ClientService clients) {
        this.clients = clients;
    }

    @GetMapping
    public List<ClientView> list() {
        return clients.list().stream().map(ClientView::from).toList();
    }

    @GetMapping("/{id}")
    public ClientView get(@PathVariable String id) {
        return ClientView.from(clients.get(id));
    }

    @PostMapping
    public ResponseEntity<ClientView> create(@Valid @RequestBody ClientRequest req) {
        var c = clients.create(req.name(), req.contact(), req.tier(), req.compliance(), CurrentUser.email());
        return ResponseEntity.status(201).body(ClientView.from(c));
    }
}
