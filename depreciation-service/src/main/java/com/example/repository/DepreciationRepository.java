package com.example.repository;

import com.example.model.Depreciation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Date;
import java.util.List;
import java.util.Optional;

public interface DepreciationRepository extends JpaRepository<Depreciation,Long> {
    List<Depreciation> findByAssetId(Long assetId);
    List<Depreciation> findByAssetIdOrderByIdAsc(Long assetId);
    @Query(value = "SELECT * FROM public.depreciation WHERE public.depreciation.to_date IS NULL AND asset_id=?1",
            countQuery = "SELECT * FROM public.depreciation WHERE public.depreciation.to_date IS NULL AND asset_id=?1",
            nativeQuery = true)
    Optional<Depreciation> findDepreciationIsNull(Long assetId);
    @Query(value = "SELECT * FROM public.depreciation WHERE public.depreciation.to_date IS NULL",
            countQuery = "SELECT * FROM public.depreciation WHERE public.depreciation.to_date IS NULL",
            nativeQuery = true)
    List<Depreciation> getAllDepreciationNoToDate();
    @Query(value = "SELECT * FROM public.depreciation WHERE (from_date >= ?1 AND from_date <=?2) OR (to_date IS NULL AND exp_date >=?1)",nativeQuery = true)
    List<Depreciation> getDepreciationByFromDateAndToDate(Date fromDate, Date toDate);
    @Query(value = "SELECT asset_id,MAX(to_date), SUM(value_depreciation) " +
            "FROM public.depreciation " +
            "WHERE asset_id = ?1 " +
            "GROUP BY asset_id",nativeQuery = true)
    Object findLastDepreciationByAssetId(Long assetId);
    @Query(value = "SELECT *\n" +
            "FROM public.depreciation\n" +
            "WHERE to_date IS NULL AND asset_id = ?1",nativeQuery = true)
    Optional<Depreciation> findByAssetIdAndToDate(Long assetId);

}
