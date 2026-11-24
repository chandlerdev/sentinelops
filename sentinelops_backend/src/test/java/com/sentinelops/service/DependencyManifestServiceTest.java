package com.sentinelops.service;

import com.sentinelops.entity.DependencyEcosystem;
import com.sentinelops.entity.Target;
import com.sentinelops.entity.TargetKind;
import com.sentinelops.repository.DependencyManifestRepository;
import com.sentinelops.repository.TargetRepository;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DependencyManifestServiceTest {

    private static final String LOCKFILE = "{\"lockfileVersion\":3,\"packages\":{}}";

    private DependencyManifestService service(Target t) {
        var targets = mock(TargetRepository.class);
        when(targets.findById(t.getId())).thenReturn(Optional.of(t));
        return new DependencyManifestService(mock(DependencyManifestRepository.class), targets,
                mock(AccessService.class), mock(AuditService.class));
    }

    @Test
    void acceptsAWellFormedManifest() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(t);
        var view = svc.create("e1", "t1", "Backend lockfile", DependencyEcosystem.NPM, LOCKFILE, "tess");
        assertEquals("Backend lockfile", view.label());
        assertEquals(DependencyEcosystem.NPM, view.ecosystem());
        assertEquals(LOCKFILE.length(), view.contentLength());
    }

    @Test
    void rejectsNonJsonContent() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(t);
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L", null, "not json", "tess"));
    }

    @Test
    void rejectsJsonThatDoesNotLookLikeALockfile() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(t);
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L", null, "{\"hello\":\"world\"}", "tess"));
    }

    @Test
    void rejectsAnOverlyLargeManifest() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(t);
        String huge = "{\"lockfileVersion\":3,\"packages\":{}," + "\"x\":\"" + "a".repeat(4_000_010) + "\"}";
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L", null, huge, "tess"));
    }

    @Test
    void defaultsToNpmEcosystem() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(t);
        var view = svc.create("e1", "t1", "L", null, LOCKFILE, "tess");
        assertEquals(DependencyEcosystem.NPM, view.ecosystem());
    }
}
