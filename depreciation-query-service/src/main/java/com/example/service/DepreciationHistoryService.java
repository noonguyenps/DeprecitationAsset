package com.example.service;

import com.example.model.Depreciation;
import com.example.model.DepreciationHistory;

import java.util.List;

public interface DepreciationHistoryService {
    List<DepreciationHistory> findByDepreciation(Depreciation depreciation);
    Object getValueHistoryByDepreciation(int month, int year, Long depreciationId);
    List<Object> getDepreciationByAllDept(int year);
    List<Object> getDepreciationByDeptIds(int year,List<Long> deptIds);
    Double totalValueDepreciation();
    Double getTotalValueByDeptIdAndAssetType(Long deptId, Long assetTypeId, int year);
    Double totalValueDepreciationByAssetId(Long assetId, int month, int year);
    Double getTotalValueByDeptId(Long deptId, int year);
}
