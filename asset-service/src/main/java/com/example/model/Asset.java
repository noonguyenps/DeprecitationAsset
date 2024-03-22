package com.example.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name = "assets")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Asset {
    @Id
    @Column(name = "asset_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long assetId;
    @Column(name = "asset_name")
    private String assetName;
    @Column(name = "asset_image")
    private String assetImage;
    @Column(name = "asset_status")
    private Long assetStatus;
    @Column(name = "asset_depreciation_time")
    private Long time;
    @Column(name="serial_number")
    private String serialNumber;
    @Column(name = "asset_type")
    private Long assetType;
    @Column(name = "price")
    private Double price;
    @Column(name = "date_in_stored")
    private Date dateInStored;
    @Column(name = "user_used_id")
    private Long userUsedId;
    @Column(name = "dept_used_id")
    private Long deptUsedId;
    @Column(name = "date_used")
    private Date dateUsed;
    @Column(name = "date_exp")
    private Date dateExperience;
    @Column(name = "active")
    private boolean active;
    @Column(name = "storage_id")
    private Long storageId;
    @Column(name= "brand_id")
    private Long brandId;
    @Column(name= "update_id")
    private Long updateId;
}
