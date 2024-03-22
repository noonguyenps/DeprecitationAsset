package com.example.dto.response;

import com.example.model.Accessary;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AssetResponse {
    private Long assetId;
    private String assetName;
    private String assetImage;
    private long assetTypeId;
    private String assetTypeName;
    private int amountOfYear;
    private int assetGroupId;
    private Long assetBrandId;
    private boolean active;
    private Long updateId;
    private String assetBrandName;
    private Long assetStorageId;
    private String assetStorageName;
    private String assetGroup;
    private Long status;
    private String statusName;
    private Double price;
    private String dateUsed;
    private Long userIdUsed;
    private Long deptIdUsed;
    private UserResponse user;
    private String dateInStored;
    private String serial;
    private String expDate;
    private Double valuePerMonth;
    private List<Accessary> accessaries;
}
