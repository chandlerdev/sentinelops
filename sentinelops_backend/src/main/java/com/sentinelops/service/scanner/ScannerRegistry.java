package com.sentinelops.service.scanner;

import com.sentinelops.entity.ScanCategory;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

/** The tools the platform knows. Which tools a category uses is decided here, never by a client. */
@Component
public class ScannerRegistry {

    private final List<ScannerAdapter> adapters;

    public ScannerRegistry(List<ScannerAdapter> adapters) {
        this.adapters = List.copyOf(adapters);
    }

    public Optional<ScannerAdapter> get(String id) {
        return adapters.stream().filter(a -> a.id().equals(id)).findFirst();
    }

    /** The tools that apply to THIS scan (category, effective mode, target details). */
    public List<ScannerAdapter> forScan(ScanCategory category, com.sentinelops.entity.ScanMode mode, ScanContext ctx) {
        return adapters.stream().filter(a -> a.supports(category, mode, ctx)).toList();
    }

    public List<ScannerAdapter> forCategory(ScanCategory category) {
        return adapters.stream().filter(a -> a.supports(category)).toList();
    }
}
