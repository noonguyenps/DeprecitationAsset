package com.example.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashMap;
import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AssetType {
    private Long typeId;
    private String typeName;
    private Double totalPrice =0.0;
    private Double depreciationPrev= 0.0;
    private Double total1=0.0;
    private Double total2=0.0;
    private Double total3=0.0;
    private Double total4=0.0;
    private Map<String,Double> months = new HashMap<>();
}
