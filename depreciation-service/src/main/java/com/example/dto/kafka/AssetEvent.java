package com.example.dto.kafka;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AssetEvent {
    private String eventType;
    private AssetResponse assetResponse = new AssetResponse();
    @Data
    @NoArgsConstructor
    public class AssetResponse{
        private Long assetId;
        private Long userId;
        private Long deptId;

        public AssetResponse(Long assetId, Long userId, Long deptId) {
            this.assetId = assetId;
            this.userId = userId;
            this.deptId = deptId;
        }
    }
}
