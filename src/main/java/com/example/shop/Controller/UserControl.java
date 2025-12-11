package com.example.shop.Controller;
import com.example.shop.Entity.User;
import com.example.shop.Security.JwtUtil;
import com.example.shop.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import java.util.Optional;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class UserControl {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private JwtUtil jwtUtil;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody User user) {

        if (user.getUsername() == null || user.getEmail() == null
                || user.getPassword() == null || user.getPhoneno() == null) {
            return ResponseEntity.badRequest().body("All fields are required");
        }

        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("Username already exists");
        }
        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            return ResponseEntity.badRequest().body("Email already exists");
        }
        if (userRepository.findByPhoneno(user.getPhoneno()).isPresent()) {
            return ResponseEntity.badRequest().body("Phone number already exists");
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));

        User savedUser = userRepository.save(user);

        return ResponseEntity.ok(savedUser);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {

        String username = body.get("username");
        String password = body.get("password");
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            return ResponseEntity.badRequest().body("Invalid username or password");
        }
        User user = userOpt.get();
        if (!passwordEncoder.matches(password, user.getPassword())) {
            return ResponseEntity.badRequest().body("Invalid username or password");
        }
        String token = jwtUtil.generateToken(user.getEmail());
        return ResponseEntity.ok(Map.of(
                "token", token,
                "username", user.getUsername(),
                "email", user.getEmail(),
                "phoneno", user.getPhoneno()
        ));
    }



    @GetMapping("/test")
    public String test() {
        return "Signup working!";
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getProfile() {
        return ResponseEntity.ok("You are authorized!");
    }

}
