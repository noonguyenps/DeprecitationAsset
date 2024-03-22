package com.example.service.Impl;

import com.example.dto.response.DepreciationHistoryEvent;
import com.example.model.Depreciation;
import com.example.model.DepreciationHistory;
import com.example.repository.DepreciationHistoryRepository;
import com.example.service.DepreciationHistoryService;
import lombok.AllArgsConstructor;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@AllArgsConstructor
public class DepreciationHistoryServiceImpl implements DepreciationHistoryService {
    private final DepreciationHistoryRepository depreciationHistoryRepository;
    @KafkaListener(topics = "depreciation-history-event-topic",groupId = "depreciation-event-group")
    public void processDepreciationHistoryEvents(DepreciationHistoryEvent event) {
        if(event.getEventType().equals("CreateHistoryDepreciation"))
           depreciationHistoryRepository.save(event.getDepreciationHistory());
    }
    @Override
    public List<DepreciationHistory> findByDepreciation(Depreciation depreciation){
        return depreciationHistoryRepository.findByDepreciation(depreciation);
    }

    @Override
    public Object getValueHistoryByDepreciation(int month, int year, Long depreciationId) {
        return depreciationHistoryRepository.getAssetDepreciationHistoryByDepreciationId(month, year, depreciationId);
    }

    @Override
    public List<Object> getDepreciationByAllDept(int year) {
        return depreciationHistoryRepository.getDepreciationByAllDept(year);
    }

    @Override
    public List<Object> getDepreciationByDeptIds(int year, List<Long> deptIds) {
        return depreciationHistoryRepository.getDepreciationByDeptIds(deptIds,year);
    }
    @Override
    public Double totalValueDepreciation(){
        return depreciationHistoryRepository.totalValueDepreciation();
    }
    @Override
    public Double getTotalValueByDeptIdAndAssetType(Long deptId, Long assetTypeId,int year){
        Double result = depreciationHistoryRepository.getTotalValueByDeptIdAndAssetType(deptId,assetTypeId,year);
        if(result==null)
            return 0.0;
        return result;
    }

    @Override
    public Double totalValueDepreciationByAssetId(Long assetId, int month, int year) {
        return depreciationHistoryRepository.totalValueDepreciationByAssetId(assetId, month, year);
    }

    @Override
    public Double getTotalValueByDeptId(Long deptId, int year) {
        Double result = depreciationHistoryRepository.getTotalValueByDeptId(deptId,year);
        if(result==null)
            return 0.0;
        return result;
    }

}
