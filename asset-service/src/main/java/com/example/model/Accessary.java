package com.example.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "accessary")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Accessary {
    @Id
    @Column(name = "id")
    private Long id;
    @Column(name = "asset_id")
    private Long assetId;
    @Column(name = "name")
    private String name;
    @Column(name = "unit")
    private String unit;
    @Column(name = "amount")
    private int amount;
    @Column(name = "price")
    private Double price;
}
