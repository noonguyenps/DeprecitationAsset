package com.example.repository;

import com.example.model.Depreciation;
import com.example.model.DepreciationHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface DepreciationHistoryRepository extends JpaRepository<DepreciationHistory, Long> {
    List<DepreciationHistory> findByDepreciation(Depreciation depreciation);
    //Lấy ra danh sách các khấu hao cho tất cả phòng ban
    @Query(value = "SELECT dept_id, depreciation_history_query.asset_type_id, month, year, sum(value) as value \n" +
            "FROM depreciation_history_query, depreciation_query\n" +
            "WHERE year = ?1 AND depreciation_history_query.depreciation_id = depreciation_query.id\n" +
            "GROUP BY dept_id, depreciation_history_query.asset_type_id, month, year",nativeQuery = true)
    List<Object> getDepreciationByAllDept(int year);
    @Query(value = "SELECT dept_id, depreciation_history_query.asset_type_id, month, year, sum(value) as value \n" +
            "FROM depreciation_history_query, depreciation_query\n" +
            "WHERE dept_id in ?1 AND year = ?2 AND depreciation_history_query.depreciation_id = depreciation_query.id\n" +
            "GROUP BY dept_id, depreciation_history_query.asset_type_id, month, year",nativeQuery = true)
    List<Object> getDepreciationByDeptIds(List<Long> deptIds,int year);
    @Query(value = "SELECT depreciation_id , SUM(value)\n" +
            "FROM depreciation_history_query\n" +
            "WHERE ((month < ?1 AND year = ?2) OR (year < ?2)) AND depreciation_id = ?3\n" +
            "GROUP BY depreciation_id",nativeQuery = true)
    Object getAssetDepreciationHistoryByDepreciationId(int month,int year, Long depreciationId);
    @Query(value = "SELECT SUM(value)\n" +
            "FROM depreciation_history_query",nativeQuery = true)
    Double totalValueDepreciation();
    @Query(value = "SELECT sum(\"value\")" +
            "FROM depreciation_history_query " +
            "WHERE asset_id = ?1 AND ((month < ?2 AND year=?3) OR year<?3)" +
            "GROUP BY asset_id",nativeQuery = true)
    Double totalValueDepreciationByAssetId(Long assetId,int month, int year);
    @Query(value = "SELECT SUM(value)\n" +
            "FROM depreciation_history_query, depreciation_query\n" +
            "WHERE depreciation_query.id = depreciation_history_query.depreciation_id " +
            "AND dept_id = ?1 AND depreciation_history_query.asset_type_id= ?2 AND year < ?3\n" +
            "GROUP BY dept_id, depreciation_history_query.asset_type_id", nativeQuery = true)
    Double getTotalValueByDeptIdAndAssetType(Long deptId, Long assetTypeId, int year);
    @Query(value = "SELECT SUM(value)\n" +
            "FROM depreciation_history_query, depreciation_query\n" +
            "WHERE depreciation_query.id = depreciation_history_query.depreciation_id " +
            "AND dept_id = ?1  AND year < ?2\n" +
            "GROUP BY dept_id", nativeQuery = true)
    Double getTotalValueByDeptId(Long deptId, int year);
}
