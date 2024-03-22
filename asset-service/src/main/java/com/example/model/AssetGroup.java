package com.example.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.List;

@Entity
@Table(name = "assets_group")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class AssetGroup {
    @Id
    @Column(name="id")
    private int id;
    @Column(name="name")
    private String name;
    @OneToMany(mappedBy = "assetGroup",cascade = CascadeType.ALL)
    private List<AssetType> listAssetType;
}
