package com.example.repository;

import com.example.model.Depreciation;
import com.example.model.DepreciationHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface DepreciationHistoryRepository extends JpaRepository<DepreciationHistory, Long> {
    List<DepreciationHistory> findByDepreciation(Depreciation depreciation);
    @Query(value = "SELECT asset_id , SUM(value)\n" +
            "FROM depreciation_history\n" +
            "WHERE (month < ?1 AND year = ?2) OR (year < ?2)\n" +
            "GROUP BY asset_id",nativeQuery = true)
    List<Object> getAssetDepreciationHistory(int month,int year);
    Optional<DepreciationHistory> findByMonthAndYear(int month, int year);
    @Query(value = "SELECT asset_id , SUM(value)\n" +
            "FROM depreciation_history\n" +
            "WHERE month = ?1 AND year = ?2 AND asset_id = ?3\n" +
            "GROUP BY asset_id",nativeQuery = true)
    Object getValueByMonthAndValueAndId(int month, int year, Long assetId);
    @Query(value = "SELECT month , SUM(value)\n" +
            "FROM depreciation_history\n" +
            "WHERE year = ?1 AND asset_id = ?2\n" +
            "GROUP BY asset_id, month",nativeQuery = true)
    List<Object> getValueByYearAndId(int year, Long assetId);
    @Query(value = "SELECT asset_id , SUM(value)\n" +
            "FROM depreciation_history\n" +
            "WHERE ((month < ?1 AND year = ?2) OR (year < ?2)) AND asset_id = ?3\n" +
            "GROUP BY asset_id",nativeQuery = true)
    Object getAssetDepreciationHistoryByAssetId(int month,int year, Long assetId);

    //Lấy ra danh sách các khấu hao cho tất cả phòng ban
    @Query(value = "SELECT dept_id, depreciation_history.asset_type_id, month, year, sum(value) as value \n" +
            "FROM depreciation_history, depreciation\n" +
            "WHERE year = ?1 AND depreciation_history.depreciation_id = depreciation.id\n" +
            "GROUP BY dept_id, depreciation_history.asset_type_id, month, year",nativeQuery = true)
    List<Object> getDepreciationByAllDept(int year);
    @Query(value = "SELECT dept_id, depreciation_history.asset_type_id, month, year, sum(value) as value \n" +
            "FROM depreciation_history, depreciation\n" +
            "WHERE dept_id in ?1 AND year = ?2 AND depreciation_history.depreciation_id = depreciation.id\n" +
            "GROUP BY dept_id, depreciation_history.asset_type_id, month, year",nativeQuery = true)
    List<Object> getDepreciationByDeptIds(List<Long> deptIds,int year);
    @Query(value = "SELECT dept_id, depreciation_history.asset_type_id, month, SUM(value)\n" +
            "FROM depreciation, depreciation_history\n" +
            "WHERE depreciation.id = depreciation_history.depreciation_id AND year = ?1 AND dept_id = ?2\n" +
            "GROUP BY dept_id, depreciation_history.asset_type_id, month",nativeQuery = true)
    List<Object> getDepreciationByAllDeptInYear(int year, Long deptId);

    @Query(value = "SELECT depreciation_id , SUM(value)\n" +
            "FROM depreciation_history\n" +
            "WHERE ((month < ?1 AND year = ?2) OR (year < ?2)) AND depreciation_id = ?3\n" +
            "GROUP BY depreciation_id",nativeQuery = true)
    Object getAssetDepreciationHistoryByDepreciationId(int month,int year, Long depreciationId);
    @Query(value = "SELECT SUM(value)\n" +
            "FROM depreciation_history",nativeQuery = true)
    Double totalValueDepreciation();
    @Query(value = "SELECT sum(\"value\") " +
            "FROM \"public\".depreciation_history " +
            "WHERE asset_id = ?1 " +
            "GROUP BY asset_id;",nativeQuery = true)
    Double totalValueDepreciationByAssetId(Long assetId);
    @Query(value = "SELECT sum(\"value\")" +
            "FROM \"public\".depreciation_history " +
            "WHERE asset_id = ?1 AND ((month < ?2 AND year=?3) OR year<?3)" +
            "GROUP BY asset_id",nativeQuery = true)
    Double totalValueDepreciationByAssetId(Long assetId,int month, int year);
    @Query(value = "SELECT sum(\"value\")" +
            "FROM \"public\".depreciation_history " +
            "WHERE depreciation_id = ?1 AND ((month < ?2 AND year=?3) OR year<?3)" +
            "GROUP BY depreciation_id;",nativeQuery = true)
    Double totalValueDepreciationByDepreciationId(Long depreciationId,int month, int year);
    @Query(value = "SELECT SUM(value)\n" +
            "FROM depreciation_history, depreciation\n" +
            "WHERE depreciation.id = depreciation_history.depreciation_id " +
            "AND dept_id = ?1 AND depreciation_history.asset_type_id= ?2 AND year < ?3\n" +
            "GROUP BY dept_id, depreciation_history.asset_type_id", nativeQuery = true)
    Double getTotalValueByDeptIdAndAssetType(Long deptId, Long assetTypeId, int year);
    @Query(value = "SELECT SUM(value)\n" +
            "FROM depreciation_history, depreciation\n" +
            "WHERE depreciation.id = depreciation_history.depreciation_id " +
            "AND dept_id = ?1  AND year < ?2\n" +
            "GROUP BY dept_id", nativeQuery = true)
    Double getTotalValueByDeptId(Long deptId, int year);
}
