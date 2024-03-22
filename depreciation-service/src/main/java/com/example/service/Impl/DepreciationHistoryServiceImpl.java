package com.example.service.Impl;

import com.example.dto.response.DepreciationHistoryEvent;
import com.example.model.DepreciationHistory;
import com.example.repository.DepreciationHistoryRepository;
import com.example.service.DepreciationHistoryService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class DepreciationHistoryServiceImpl implements DepreciationHistoryService {
    @Autowired
    private DepreciationHistoryRepository depreciationHistoryRepository;
    @Autowired
    private KafkaTemplate<String,Object> kafkaTemplate;

    @Override
    public boolean saveDepreciationHistory(DepreciationHistory depreciationHistory) {
        DepreciationHistory depreciationHistoryTemp = depreciationHistoryRepository.save(depreciationHistory);
        DepreciationHistoryEvent event = new DepreciationHistoryEvent("CreateHistoryDepreciation",depreciationHistoryTemp);
        kafkaTemplate.send("depreciation-history-event-topic", event);
        return true;
    }

    @Override
    public Double totalValueDepreciationByAssetId(Long assetId) {
        return depreciationHistoryRepository.totalValueDepreciationByAssetId(assetId);
    }

    @Override
    public Double totalValueDepreciationByDepreciationId(Long depreciationId, int month, int year) {
        return depreciationHistoryRepository.totalValueDepreciationByDepreciationId(depreciationId, month, year);
    }

    @Override
    public Double totalValueDepreciationByAssetId(Long assetId, int month, int year) {
        return depreciationHistoryRepository.totalValueDepreciationByAssetId(assetId, month, year);
    }

}
