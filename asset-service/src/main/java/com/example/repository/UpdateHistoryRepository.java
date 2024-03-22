package com.example.repository;

import com.example.model.UpdateHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Date;
import java.util.List;

public interface UpdateHistoryRepository extends JpaRepository<UpdateHistory, Long> {
    public List<UpdateHistory> findByAssetId(Long assetId);
    @Query(value = "SELECT *\n" +
            "FROM public.update_history\n" +
            "WHERE value>0 AND asset_id = ?1",nativeQuery = true)
    List<UpdateHistory> getHistoryUpdateById(Long assetId);
    @Query(value = "SELECT *\n" +
            "FROM public.update_history\n" +
            "WHERE value<0 AND asset_id = ?1",nativeQuery = true)
    List<UpdateHistory> getHistoryReduceById(Long assetId);
    UpdateHistory findByAssetIdAndCreateAt(Long assetId, Date date);

}
