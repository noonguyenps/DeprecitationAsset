package com.example.dto.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UpdateHistoryRequest {
    private Double value;
    private Long month;
    private String note;
    private String status;
    private String dateUpdate;
}
