package com.example.client;

import com.example.dto.request.DepreciationRequest;
import com.example.dto.response.UserResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class AssetServiceClient {
    @Autowired
    private RestTemplate template;

    public UserResponse fetchUser(Long userId) {
        return template.getForObject("http://USER-SERVICE/api/user/v1/" + userId, UserResponse.class);
    }

    public void addDepreciation(DepreciationRequest depreciationRequest) {
        template.postForEntity("http://DEPRECIATION-SERVICE/api/depreciation/create", depreciationRequest,String.class);
    }
    public Boolean recallAsset(Long assetId) {
        return template.postForObject("http://DEPRECIATION-SERVICE/api/depreciation/recall/" + assetId,null,Boolean.class);
    }
}
