package com.example.shop.Controller;

import com.example.shop.Repository.OtpRepository;
import com.example.shop.Repository.UserRepository;
import com.example.shop.Entity.Otp;
import com.example.shop.Entity.User;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import java.util.*;
import java.time.LocalDateTime;

@RestController
@RequestMapping("/api")
public class OtpControl {

    private final OtpRepository otpRepository;
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public OtpControl(OtpRepository otpRepository, UserRepository userRepository) {
        this.otpRepository = otpRepository;
        this.userRepository = userRepository;
    }

    @Value("${MAILERSEND_API_KEY}")
    private String mailerApiKey;

    public void sendOtpEmail(String to, String otp) throws Exception {
        String html = "<h2>Your OTP Code</h2>" +
                "<p>Your verification OTP is: <b>" + otp + "</b></p>" +
                "<p>This OTP will expire in 10 minutes.</p>";

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode json = mapper.createObjectNode();

        ObjectNode from = json.putObject("from");
        from.put("email", "MS_UQsS9L@test-dnvo4d93pxxg5r86.mlsender.net");
        from.put("name", "OnlineShop App");

        ArrayNode toArr = json.putArray("to");
        ObjectNode toObj = toArr.addObject();
        toObj.put("email", to);

        json.put("subject", "Your OTP Code");
        json.put("html", html);

        String body = mapper.writeValueAsString(json);

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.mailersend.com/v1/email"))
                .header("Authorization", "Bearer " + mailerApiKey)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() >= 300) {
            throw new RuntimeException("MailerSend Error: " + response.body());
        }
    }


    @PostMapping("/forget")
    public ResponseEntity<?> forget(@RequestBody Map<String, String> body) {

        String email = body.get("email");

        if (email == null || email.isEmpty()) {
            return ResponseEntity.badRequest().body("Email is required");
        }

        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isEmpty()) {
            return ResponseEntity.badRequest().body("Email does not exist");
        }

        String otp = String.format("%06d", new Random().nextInt(1_000_000));

        Otp token = new Otp(email, otp, LocalDateTime.now().plusMinutes(10));
        otpRepository.save(token);

        try {
            sendOtpEmail(email, otp);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Failed to send OTP: " + e.getMessage());
        }

        return ResponseEntity.ok("OTP sent to email");
    }

    @PostMapping("verifyotp")
    public ResponseEntity<?> verifyOtp(@RequestBody Map<String, String> body) {

        String email = body.get("email");
        String otp = body.get("otp");

        Optional<Otp> otpRecord =
                otpRepository.findTopByEmailAndOtpAndUsedFalseOrderByIdDesc(email, otp);

        if (otpRecord.isEmpty()) {
            return ResponseEntity.badRequest().body("Invalid or expired OTP");
        }

        Otp token = otpRecord.get();

        if (token.getExpiresAt().isBefore(LocalDateTime.now())) {
            return ResponseEntity.badRequest().body("OTP Expired");
        }

        token.setUsed(true);
        otpRepository.save(token);

        return ResponseEntity.ok("OTP verified");
    }

    @PostMapping("resetpassword")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> body) {

        String email = body.get("email");
        String newPassword = body.get("password");

        Optional<User> userOpt = userRepository.findByEmail(email);

        if (userOpt.isEmpty()) {
            return ResponseEntity.badRequest().body("User not found");
        }

        User user = userOpt.get();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        return ResponseEntity.ok("Password updated successfully");
    }

    @GetMapping("/test-api-key")
    public ResponseEntity<String> testApiKey() {
        return ResponseEntity.ok("MailerSend API Key: " + mailerApiKey);
    }
}
