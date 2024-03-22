package com.example.controller;

import com.example.dto.request.DepreciationRequest;
import com.example.mapping.DepreciationHistoryMapping;
import com.example.mapping.DepreciationMapping;
import com.example.model.Depreciation;
import com.example.service.DepreciationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.text.ParseException;

@RestController
@RequestMapping("/api/depreciation")
@RequiredArgsConstructor

public class DepreciationController {
//    private final DepreciationMapping depreciationMapping;
//    private final DepreciationService depreciationService;
//    private final DepreciationHistoryMapping depreciationHistoryMapping;
//    //Tạo thông tin khấu hao
//    @PostMapping("/create")
//    public ResponseEntity saveDepreciation(@RequestBody DepreciationRequest depreciationRequest) throws ParseException {
//        Depreciation depreciation = depreciationService.findByAssetIdAndToDate(depreciationRequest.getAssetId());
//        if(depreciation!=null)
//            return new ResponseEntity(new String("Thông tin khấu hao đã tồn tại"), HttpStatus.NOT_ACCEPTABLE);
//        Object object = depreciationService.findLDateAndSumValueByAssetId(depreciationRequest.getAssetId());
//        Depreciation depreciationRecords = depreciationMapping.requestToEntity(depreciationRequest, object);
//        Depreciation depreciationAdded = depreciationService.createDepreciation(depreciationRecords);
//        //Thêm lịch sử khấu hao nếu mất tháng
//        depreciationHistoryMapping.addDepreciationHistory(depreciationAdded);
//        return new ResponseEntity(new String("Thông tin khấu hao đã được tạo"), HttpStatus.CREATED);
//    }
//
//    //API Thực hiện tính toán và ngưng khấu hao
//    @PostMapping("/recall/{id}")
//    public ResponseEntity updateDepreciation(@PathVariable Long id) throws ParseException {
//        Depreciation depreciation = depreciationService.findDepreciationToUpdate(id);
//        if(depreciation == null)
//            return new ResponseEntity("Thông tin khấu hao không tồn tại", HttpStatus.NOT_FOUND);
//        depreciation = depreciationMapping.updateDepreciation(depreciation);
//        depreciationService.saveDepreciation(depreciation);
//            return new ResponseEntity(true, HttpStatus.CREATED);
//    }
}
