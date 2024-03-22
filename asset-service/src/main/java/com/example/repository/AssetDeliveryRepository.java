package com.example.repository;

import com.example.model.AssetDelivery;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface AssetDeliveryRepository extends JpaRepository<AssetDelivery, Long> {
    List<AssetDelivery> findByAssetIdAndStatus(Long assetId, int status);
    List<AssetDelivery> findByAssetIdAndDeliveryType(Long assetId,int deliveryType);
    @Query(value = "SELECT * FROM asset_delivery WHERE asset_id=?1 AND (delivery_type= 0 OR delivery_type=1) AND active = true ORDER BY create_at",nativeQuery = true)
    List<AssetDelivery> findByAssetIdAndDeliveryType(Long assetId);

    @Query(value = "SELECT * FROM asset_delivery WHERE asset_id=?1 AND user_id = ?2 AND delivery_type= ?3 AND active = true ORDER BY create_at LIMIT 1",nativeQuery = true)
    AssetDelivery findByAssetIdAndDeliveryType(Long assetId,Long userId, Long type);
}
