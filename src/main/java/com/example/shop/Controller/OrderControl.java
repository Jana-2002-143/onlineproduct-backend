package com.example.shop.Controller;

import com.example.shop.Entity.Order;
import com.example.shop.Repository.OrderRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class OrderControl {

    @Autowired
    private OrderRepository orderRepository;

    @PostMapping("/order")
    public ResponseEntity<?> order(@RequestBody Order order) {
        Order savedOrder = orderRepository.save(order);
        return ResponseEntity.ok(savedOrder);
    }

    @GetMapping("/history/{buyerName}")
    public ResponseEntity<List<Order>> getUserHistory(@PathVariable String buyerName) {
        List<Order> userOrders = orderRepository.findByBuyerName(buyerName);
        return ResponseEntity.ok(userOrders);
    }
}
