package com.example.service.Impl;

import com.example.model.AssetType;
import com.example.repository.AssetTypeRepository;
import com.example.service.AssetTypeService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
public class AssetTypeServiceImpl implements AssetTypeService {
    private final AssetTypeRepository assetTypeRepository;

    @Override
    public List<AssetType> getAllAsset() {
        return assetTypeRepository.findAll();
    }

    @Override
    public AssetType findAssetTypeById(Long id) {
        Optional<AssetType> assetType = assetTypeRepository.findById(id);
        if(assetType.isEmpty())
            return null;
        return assetType.get();
    }
}
