package com.example.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name = "asset_delivery")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class AssetDelivery {
    @Id
    @Column(name = "delivery_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "asset_id")
    private Long assetId;
    @Column(name = "user_id")
    private Long userId;
    @Column(name = "user_create_id")
    private Long userCreateId;
    @Column(name = "dept_id")
    private Long deptId;
    @Column(name = "status")
    private Long status;
    @Column(name = "delivery_type")
    private int deliveryType;
    @Column(name = "note")
    private String note;
    @Column(name="create_at")
    private Date createAt;
    @Column(name ="active")
    private boolean active = true;
}
