package com.example.service;

import com.example.model.Depreciation;
import com.example.model.DepreciationHistory;

import java.util.List;

public interface DepreciationHistoryService {
    boolean saveDepreciationHistory(DepreciationHistory depreciationHistory);
    Double totalValueDepreciationByAssetId(Long assetId);
    Double totalValueDepreciationByDepreciationId(Long depreciationId, int month, int year);
    Double totalValueDepreciationByAssetId(Long assetId, int month, int year);
}
