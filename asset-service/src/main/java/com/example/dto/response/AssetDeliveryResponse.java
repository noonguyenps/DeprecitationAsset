package com.example.dto.response;

import lombok.Data;

import java.util.List;
@Data
public class AssetDeliveryResponse {
    private Long storageId;
    private String storageName;
    private String storageLocation;
    private UserResponse userResponse;
    private String dateInStored;
    private String dateUsed;
    private List<DeliveryHistory> deliveryHistories;
    private List<DeliveryHistory> brokenHistories;
    @Data
    public static class DeliveryHistory{
        private UserResponse userResponse;
        private UserResponse userCreateResponse;
        private String deliveryDate;
        private Long status;
        private String deliveryType;
        private String note;
    }
}
