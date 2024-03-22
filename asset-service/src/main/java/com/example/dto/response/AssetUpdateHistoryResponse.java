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
public class AssetUpdateHistoryResponse {
    private Long assetId;
    private String assetName;
    private Double pricePrev;
    private Double pricePre;
    private Double totalValueUpdate;
    private String dateUpdateNearest;
    private String note;
    private Long timePrev;
    private Long timePre;
    private List<UpdateHistoryResponse> updateHistoryResponses;
    @Data
    public static class UpdateHistoryResponse{
        private Long historyId;
        private UserResponse userUpdate;
        private UserResponse userUsed;
        private String requestDate;
        private String updateDate;
        private Double value;
        private Double valuePrev;
        private Long amountMonth;
        private String note;
        private String status;

        public UpdateHistoryResponse(Long historyId, UserResponse userUpdate, UserResponse userUsed, String requestDate, String updateDate, Double value, Double valuePrev, Long amountMonth, String note,String status) {
            this.historyId = historyId;
            this.userUpdate = userUpdate;
            this.userUsed = userUsed;
            this.requestDate = requestDate;
            this.updateDate = updateDate;
            this.value = value;
            this.valuePrev = valuePrev;
            this.amountMonth = amountMonth;
            this.note = note;
            this.status = status;
        }
    }
}
