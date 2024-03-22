package com.example.service;

import com.example.model.UpdateHistory;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;

@Service
@Component
public interface UpdateHistoryService {
    List<UpdateHistory> getListUpdateHistoryByAssetId(Long assetId);

    List<UpdateHistory> getListReduceHistoryByAssetId(Long assetId);
    void save(UpdateHistory updateHistory);

    UpdateHistory findByAssetIdAndCreateAt(Long assetId, Date date);
}
