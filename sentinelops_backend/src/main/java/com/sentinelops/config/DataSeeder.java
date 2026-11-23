package com.sentinelops.config;

import com.sentinelops.entity.*;
import com.sentinelops.repository.*;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * Seeds a demo admin, a sample client and an empty engagement on first run (empty user table).
 * Guarded to the 'seed' profile so it never runs in production by accident:
 *   --spring.profiles.active=seed
 * The demo admin password comes from SEED_ADMIN_PASSWORD (no hardcoded secret).
 * Targets and authorizations are NOT seeded: they must go through verification and approval.
 */
@Component
@Profile("seed")
public class DataSeeder implements CommandLineRunner {

    private final UserRepository users;
    private final ClientRepository clients;
    private final EngagementRepository engagements;
    private final PasswordEncoder encoder;

    public DataSeeder(UserRepository users, ClientRepository clients, EngagementRepository engagements,
                      PasswordEncoder encoder) {
        this.users = users;
        this.clients = clients;
        this.engagements = engagements;
        this.encoder = encoder;
    }

    @Override
    public void run(String... args) {
        if (users.count() > 0) return;

        String adminPw = System.getenv().getOrDefault("SEED_ADMIN_PASSWORD", "");
        if (adminPw.length() < 10) {
            throw new IllegalStateException("Set SEED_ADMIN_PASSWORD (>=10 chars) to seed the demo admin.");
        }

        users.save(new User(UUID.randomUUID().toString(), "Platform Admin",
                "admin@sentinelops.local", encoder.encode(adminPw), Role.ADMIN, "SentinelOps"));

        Client client = new Client(UUID.randomUUID().toString(), "Demo Client", "ops@example.com", "Internal", null);
        clients.save(client);

        Engagement eng = new Engagement(UUID.randomUUID().toString(), "Local lab assessment", client.getId(), "Lab");
        eng.setState(TicketState.AWAITING_AUTHORIZATION);
        engagements.save(eng);

        System.out.println("[seed] demo data created. Admin: admin@sentinelops.local");
    }
}
