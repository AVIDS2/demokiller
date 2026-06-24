package com.example.controller;

import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
public class ChatController {

    @PostMapping("/api/chat")
    public Map<String, Object> chat(@RequestBody Map<String, String> body) {
        String message = body.get("message");
        System.out.println("Chat request: " + message);
        return Map.of("text", "response placeholder");
    }

    @DeleteMapping("/api/admin/users")
    public Map<String, Object> deleteUser(@RequestBody Map<String, String> body) {
        String userId = body.get("userId");
        System.out.println("Deleting user: " + userId);
        return Map.of("ok", true);
    }

    @PostMapping("/api/stripe/webhook")
    public Map<String, Object> stripeWebhook(@RequestBody Map<String, Object> event) {
        System.out.println("Webhook event: " + event.get("type"));
        return Map.of("received", true);
    }
}
