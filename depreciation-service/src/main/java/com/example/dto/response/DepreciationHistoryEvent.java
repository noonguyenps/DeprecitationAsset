package com.example.dto.response;

import com.example.model.DepreciationHistory;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class DepreciationHistoryEvent {
    private String eventType;
    private DepreciationHistory depreciationHistory;
}
