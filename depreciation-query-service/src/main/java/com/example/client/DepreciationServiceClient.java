package com.example.client;

import com.example.dto.response.AssetResponse;
import com.example.dto.response.AssetTypeResponse;
import com.example.dto.response.DepartmentResponse;
import com.example.dto.response.UserResponse;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
@NoArgsConstructor
public class DepreciationServiceClient {
    @Autowired
    @LoadBalanced
    private RestTemplate template;

    public AssetResponse fetchAsset(Long assetId) {
        return template.getForObject("http://ASSET-SERVICE/api/asset/v1/" + assetId, AssetResponse.class);
    }
    public UserResponse fetchUser(Long userId) {
        return template.getForObject("http://USER-SERVICE/api/user/v1/" + userId, UserResponse.class);
    }
    public DepartmentResponse fetchDepartment(Long deptId) {
        return template.getForObject("http://USER-SERVICE/api/user/department/v1/" + deptId, DepartmentResponse.class);
    }
    public AssetTypeResponse fetchAssetType(Long typeId) {
        return template.getForObject("http://ASSET-SERVICE/api/asset/type/" + typeId, AssetTypeResponse.class);
    }


}
