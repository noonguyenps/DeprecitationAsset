package com.example.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.Date;
@Entity
@Table(name = "storages")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Storage {
    @javax.persistence.Id
    @Column(name = "storage_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long Id;
    @Column(name = "storage_name")
    private String storageName;
    @Column(name = "storage_location")
    private String location;
    @Column(name = "active")
    private boolean active;
    @Column(name = "create_at")
    private Date createAt;
}
