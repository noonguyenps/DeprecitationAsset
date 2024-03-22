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

    Depreciation findByAssetIdAndToDate(Long assetId);

    Depreciation createDepreciation(Depreciation depreciation);

    Depreciation saveDepreciation(Depreciation depreciation);

    Depreciation findDepreciationToUpdate(Long assetId);
    List<Depreciation> getDepreciationByFromDateAndToDate(Date fromDate, Date toDate);
    Object findLDateAndSumValueByAssetId(Long assetId);
}
