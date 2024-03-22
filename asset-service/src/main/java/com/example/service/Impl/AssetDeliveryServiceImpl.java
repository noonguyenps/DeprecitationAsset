package com.example.service.Impl;

import com.example.model.AssetDelivery;
import com.example.repository.AssetDeliveryRepository;
import com.example.service.AssetDeliveryService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@AllArgsConstructor
public class AssetDeliveryServiceImpl implements AssetDeliveryService {
    private final AssetDeliveryRepository assetDeliveryRepository;
    @Override
    public List<AssetDelivery> findByAssetIdAndStatus(Long assetId, int status) {
        return assetDeliveryRepository.findByAssetIdAndStatus(assetId,status);
    }

    @Override
    public List<AssetDelivery> findByAssetIdAndDeliveryType(Long assetId, int deliveryType) {
        return assetDeliveryRepository.findByAssetIdAndDeliveryType(assetId,deliveryType);
    }

    @Override
    public List<AssetDelivery> findByAssetIdAndDeliveryType(Long assetId) {
        return assetDeliveryRepository.findByAssetIdAndDeliveryType(assetId);
    }

    @Override
    public void createDelivery(AssetDelivery assetDelivery) {
        assetDeliveryRepository.save(assetDelivery);
    }
}
