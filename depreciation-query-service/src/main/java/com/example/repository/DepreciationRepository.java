package com.example.repository;

import com.example.model.Depreciation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Date;
import java.util.List;
import java.util.Optional;

public interface DepreciationRepository extends JpaRepository<Depreciation,Long> {
    List<Depreciation> findByAssetIdOrderByIdAsc(Long assetId);

}
