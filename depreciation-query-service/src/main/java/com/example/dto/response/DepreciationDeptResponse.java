package com.example.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class DepreciationDeptResponse {
    private Long deptId;
    private String deptName;
    private Double totalPrice = 0.0;
    private Double depreciationPrev = 0.0;
    private Map<String,Double> months = new HashMap<>();
    private Double total1=0.0;
    private Double total2=0.0;
    private Double total3=0.0;
    private Double total4=0.0;
    private List<AssetType> assetTypes = new ArrayList<>();
}
