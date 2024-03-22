package com.example.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class DepreciationByAssetResponse {
    private Long assetId;
    private String assetName;
    private Double price;
    private String fromDate;
    private String expDate;
    private int amountDate;
    private int lengthOfMonth;
    private String changePrice;
    private Double valuePrev;
    private Double valuePre;
    private int amountMonth;
    private Double totalValue;
    List<DepreciationAssetHistory> listDepreciationAssetHistory;
    @Data
    public static class DepreciationAssetHistory{
        private Long depreciationId;
        private UserResponse userResponse;
        private String fromDate;
        private String toDate;
        private Double value;
        private long time;
        private List<DepreciationHistoryByDepreciation> depreciationList;

        public DepreciationAssetHistory(Long depreciationId,UserResponse userResponse, String fromDate, String toDate, Double value, long time,List<DepreciationHistoryByDepreciation> depreciationList){
            this.userResponse = userResponse;
            this.depreciationId = depreciationId;
            this.fromDate = fromDate;
            this.toDate = toDate;
            this.value =value;
            this.time = time;
            this.depreciationList = depreciationList;
        }
    }
}
