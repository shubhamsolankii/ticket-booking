package com.ticketbooking.auth.util;

import com.github.f4b6a3.ulid.UlidCreator;
import org.springframework.stereotype.Component;

@Component
public class UlidGenerator {
    public String generate(){
        return UlidCreator.getMonotonicUlid().toString();
    }
}
