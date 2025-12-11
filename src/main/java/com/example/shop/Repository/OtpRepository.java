package com.example.shop.Repository;

import com.example.shop.Entity.Otp;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OtpRepository extends JpaRepository<Otp, Long> {

    Optional<Otp> findTopByEmailAndOtpAndUsedFalseOrderByIdDesc(String email, String otp);
}