package com.example.dto.response;

import com.example.model.Depreciation;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class DepreciationEvent {
    private String eventType;
    private Depreciation depreciation;
}
