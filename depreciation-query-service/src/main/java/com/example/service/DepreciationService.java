package com.example.service;

import com.example.model.Depreciation;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;

@Component
@Service
public interface DepreciationService {
    List<Depreciation> findByAssetIdOrderByIdAsc(Long assetId);
}
