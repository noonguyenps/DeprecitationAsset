package com.example.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AssetResponse {
    private Long assetId;
    private String assetName;
    private long assetTypeId;
    private int amountOfYear;
    private String assetTypeName;
    private int assetGroupId;
    private String assetGroup;
    private Long status;
    private Long updateId;
    private String statusName;
    private Double price;
    private String dateUsed;
    private String dateInStored;
    private String expDate;
    private String serial;
}
