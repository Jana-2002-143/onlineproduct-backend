package com.example.shop.Repository;

import com.example.shop.Entity.Order;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface OrderRepository extends JpaRepository<Order, Long> {

    List<Order> findByBuyerName(String buyerName);

    List<Order> findByBuyerEmail(String buyerEmail);

    List<Order> findByQuantity(String quantity);

    List<Order> findByDate(String date);

    List<Order> findByItemName(String itemName);

    List<Order> findByPrice(String price);

    List<Order> findByImage(String image);

    List<Order> findByDebited(String debited);
}
