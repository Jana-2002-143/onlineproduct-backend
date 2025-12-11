package com.example.shop.Entity;

import jakarta.persistence.*;



@Entity
@Table(name = "orders")
public class Order {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = false)
    private String buyerName;

    @Column(nullable = false, unique = false)
    private String buyerEmail;

    @Column(nullable = false, unique = false)
    private String itemName;

    @Column(nullable = false, unique = false)
    private String image;

    @Column(nullable = false, unique = false)
    private String debited;

    @Column(nullable = false, unique = false)
    private String date;


    @Column(nullable = false, unique = false)
    private String quantity;

    @Column(nullable = false, unique = false)
    private String price;

    public Order() {
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getPrice() {return price;}

    public void setPrice(String price) {this.price = price;}

    public String getDate() {return date;}

    public void setDate(String date) {this.date = date;}

    public String getQuantity() {return quantity;}

    public void setQuantity(String quantity) {this.quantity = quantity;}

    public String getItemName() {
        return itemName;
    }

    public void setItemName(String itemName) {this.itemName = itemName;}

    public String getBuyerName() {
        return buyerName;
    }

    public void setBuyerName(String buyerName) {
        this.buyerName = buyerName;
    }

    public String getBuyerEmail() {
        return buyerEmail;
    }

    public void setBuyerEmail(String buyerEmail) {
        this.buyerEmail = buyerEmail;
    }

    public String getDebited() {
        return debited;
    }

    public void setDebited(String debited) {
        this.debited = debited;
    }

    public String getImage() {
        return image;
    }

    public void setImage(String image) {
        this.image = image;
    }
}
