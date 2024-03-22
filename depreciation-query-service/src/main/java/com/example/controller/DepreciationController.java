package com.example.controller;

import com.example.dto.response.DepreciationByAssetResponse;
import com.example.mapping.DepreciationMapping;
import com.example.model.Depreciation;
import com.example.service.DepreciationHistoryService;
import com.example.service.DepreciationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.text.ParseException;
import java.util.List;

@RestController
@RequestMapping("/api/depreciation")
@RequiredArgsConstructor

public class DepreciationController {
    private final DepreciationMapping depreciationMapping;
    private final DepreciationService depreciationService;
    private final DepreciationHistoryService depreciationHistoryService;
    //Đếm các giá trị khấu hao đến hiện tại
    @GetMapping("/count")
    public ResponseEntity countDepreciationValue(){
        return new ResponseEntity(depreciationHistoryService.totalValueDepreciation(),HttpStatus.OK);
    }
    //Thông tin khấu hao theo mỗi tài sản
    @GetMapping("/asset/{id}")
    public ResponseEntity getDepreciationByAssetId(@PathVariable Long id) throws ParseException {
        List<Depreciation> depreciationList =  depreciationService.findByAssetIdOrderByIdAsc(id);
        if(depreciationList.size()==0)
            return new ResponseEntity(HttpStatus.NOT_FOUND);
        DepreciationByAssetResponse depreciation = depreciationMapping.getDepreciationAssetResponse(id,depreciationList);
        return new ResponseEntity(depreciation,HttpStatus.OK);
    }
}
