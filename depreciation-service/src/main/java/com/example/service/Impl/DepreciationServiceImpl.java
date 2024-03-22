package com.example.service.Impl;

import com.example.dto.kafka.AssetEvent;
import com.example.dto.request.DepreciationRequest;
import com.example.dto.response.DepreciationEvent;
import com.example.mapping.DepreciationHistoryMapping;
import com.example.mapping.DepreciationMapping;
import com.example.model.Depreciation;
import com.example.model.DepreciationHistory;
import com.example.repository.DepreciationRepository;
import com.example.service.DepreciationService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
public class DepreciationServiceImpl implements DepreciationService {
    @Autowired
    private KafkaTemplate<String,Object> kafkaTemplate;
    @Autowired
    private DepreciationMapping depreciationMapping;
    @Autowired
    private DepreciationHistoryMapping depreciationHistoryMapping;

    private final DepreciationRepository depreciationRepository;

    @Override
    public Depreciation findByAssetIdAndToDate(Long assetId) {
        Optional<Depreciation> depreciation = depreciationRepository.findByAssetIdAndToDate(assetId);
        if(depreciation.isEmpty())
            return null;
        return depreciation.get();
    }

    @Override
    public Depreciation createDepreciation(Depreciation depreciation ){
        Depreciation depreciationTemp = depreciationRepository.save(depreciation);
        DepreciationEvent event = new DepreciationEvent("CreateDepreciation",depreciationTemp);
        kafkaTemplate.send("depreciation-event-topic", event);
        return depreciationTemp;
    }

    @Override
    public Depreciation saveDepreciation(Depreciation depreciation ){
        Depreciation depreciationTemp = depreciationRepository.save(depreciation);
        DepreciationEvent event = new DepreciationEvent("UpdateDepreciation",depreciationTemp);
        kafkaTemplate.send("depreciation-event-topic", event);
        return depreciationTemp;
    }

    @Override
    public Depreciation findDepreciationToUpdate(Long assetId){
        Optional<Depreciation> depreciation = depreciationRepository.findDepreciationIsNull(assetId);
        if(depreciation.isPresent())
            return depreciation.get();
        return null;
    }


    @Override
    public List<Depreciation> getDepreciationByFromDateAndToDate(Date fromDate, Date toDate) {
        return depreciationRepository.getDepreciationByFromDateAndToDate(fromDate,toDate);
    }

    @Override
    public Object findLDateAndSumValueByAssetId(Long assetId) {
        return depreciationRepository.findLastDepreciationByAssetId(assetId);
    }

    @KafkaListener(topics = "asset-add-user-event-topic",groupId = "asset-event-group")
    public void processAssetEvents(AssetEvent assetEvent) throws ParseException {
        AssetEvent resp =  new AssetEvent();
        if(assetEvent.getEventType().equals("AddUser")) {
            Depreciation depreciation = findByAssetIdAndToDate(assetEvent.getAssetResponse().getAssetId());
            if (depreciation != null) {
                resp.setEventType("RollbackAddUser");
                resp.getAssetResponse().setAssetId(assetEvent.getAssetResponse().getAssetId());
                resp.getAssetResponse().setUserId(assetEvent.getAssetResponse().getUserId());
                resp.getAssetResponse().setDeptId(assetEvent.getAssetResponse().getDeptId());
                kafkaTemplate.send("asset-rollback-event-topic", resp);
            }
            else {
                Object object = findLDateAndSumValueByAssetId(assetEvent.getAssetResponse().getAssetId());
                DepreciationRequest depreciationRequest = new DepreciationRequest(assetEvent.getAssetResponse().getAssetId(), assetEvent.getAssetResponse().getUserId(), assetEvent.getAssetResponse().getDeptId());
                Depreciation depreciationRecords = depreciationMapping.requestToEntity(depreciationRequest, object);
                Depreciation depreciationAdded = createDepreciation(depreciationRecords);
                //Thêm lịch sử khấu hao nếu mất tháng
                depreciationHistoryMapping.addDepreciationHistory(depreciationAdded);
            }
        }
    }
    //API Thực hiện tính toán và ngưng khấu hao
    @KafkaListener(topics = "asset-recall-event-topic",groupId = "asset-event-group")
    public void processAssetRecallEvents(AssetEvent assetEvent) throws ParseException {
        AssetEvent resp =  new AssetEvent();
        if(assetEvent.getEventType().equals("RecallAsset")) {
            Depreciation depreciation = findDepreciationToUpdate(assetEvent.getAssetResponse().getAssetId());
            if (depreciation == null) {
                resp.setEventType("RollbackRecall");
                resp.getAssetResponse().setAssetId(assetEvent.getAssetResponse().getAssetId());
                resp.getAssetResponse().setUserId(assetEvent.getAssetResponse().getUserId());
                resp.getAssetResponse().setDeptId(assetEvent.getAssetResponse().getDeptId());
                kafkaTemplate.send("asset-rollback-event-topic", resp);
            }
            else {
                Depreciation depreciationRecords = depreciationMapping.updateDepreciation(depreciation);
                saveDepreciation(depreciationRecords);
            }

        }
    }
}
