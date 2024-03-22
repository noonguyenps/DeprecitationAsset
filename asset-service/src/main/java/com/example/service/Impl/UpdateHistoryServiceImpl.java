package com.example.service.Impl;

import com.example.model.UpdateHistory;
import com.example.repository.UpdateHistoryRepository;
import com.example.service.UpdateHistoryService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
@Service
@Transactional
@RequiredArgsConstructor
public class UpdateHistoryServiceImpl implements UpdateHistoryService {
    private final UpdateHistoryRepository updateHistoryRepository;
    @Override
    public List<UpdateHistory> getListUpdateHistoryByAssetId(Long assetId) {
        return updateHistoryRepository.getHistoryUpdateById(assetId);
    }
    @Override
    public List<UpdateHistory> getListReduceHistoryByAssetId(Long assetId){
        return updateHistoryRepository.getHistoryReduceById(assetId);
    }

    @Override
    public void save(UpdateHistory updateHistory) {
        updateHistoryRepository.save(updateHistory);
    }
    @Override
    public UpdateHistory findByAssetIdAndCreateAt(Long assetId, Date date){
        return updateHistoryRepository.findByAssetIdAndCreateAt(assetId,date);

    }
}
