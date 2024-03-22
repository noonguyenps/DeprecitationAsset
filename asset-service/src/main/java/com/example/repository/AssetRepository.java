package com.example.repository;

import com.example.model.Asset;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Date;


public interface AssetRepository extends JpaRepository<Asset,Long> {
    Page<Asset> findByDeptUsedId(Long id, Pageable pageable);
    Page<Asset> findByUserUsedId(Long id, Pageable pageable);
    Page<Asset> findByAssetStatus(Long status, Pageable pageable);
    Page<Asset> findByAssetType(Long assetTypeId, Pageable pageable);
    @Query(value = "SELECT * FROM public.assets WHERE date_in_stored >= ?1 AND date_in_stored <= ?2 ORDER BY asset_id ASC\n",
            countQuery = "SELECT * FROM public.assets WHERE date_in_stored >= ?1 AND date_in_stored <= ?2 ORDER BY asset_id ASC\n",
            nativeQuery = true)
    Page<Asset> findByStoredDate(String fromDate, String toDate,Pageable pageable);
    @Query(value = "SELECT * FROM public.assets WHERE date_in_stored >= ?1 AND date_in_stored <= ?2 ORDER BY asset_id ASC\n",
            countQuery = "SELECT * FROM public.assets WHERE date_in_stored >= ?1 AND date_in_stored <= ?2 ORDER BY asset_id ASC\n",
            nativeQuery = true)
    Page<Asset> findByStoredDate1(Date fromDate, Date toDate, Pageable pageable);
    // ?1 = '%(in|may)%'
    @Query(value = "select * from assets where converttvkdau(lower(assets.asset_name)) SIMILAR TO ?",
            countQuery = "select * from assets where converttvkdau(lower(assets.asset_name)) SIMILAR TO ?",
            nativeQuery = true)
    Page<Asset> findByKeyword(String keyword,Pageable pageable);

    @Query(value = "SELECT * \n" +
            "FROM public.assets a \n" +
            "WHERE (?1 = '%(namenull)%' OR (converttvkdau(lower(a.asset_name)) SIMILAR TO ?1))\n" +
            "AND (?2 = -1 OR a.dept_used_id = ?2) \n" +
            "AND (?3 = -1 OR a.user_used_id = ?3)\n" +
            "AND (?4 = -1 OR a.asset_type = ?4)\n" +
            "AND (a.date_in_stored >=?5 AND a.date_in_stored <= ?6)\n"+
            "AND (?7 = -1 OR a.asset_status = ?7)",
            nativeQuery = true)
    Page<Asset> filterAssets(String keyword,Long deptId, Long userId,Long assetType, Date fromDate, Date toDate, Long status,Pageable pageable);

}
