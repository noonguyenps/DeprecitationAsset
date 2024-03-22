package com.example.dto.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AssetRequest {
    private String assetName;
    private Long status;
    private long assetTypeId;
    private Double price;
    private String serial;
    private Long brandId;
    private Long storageId;
    private String image;
}
