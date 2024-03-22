package com.example.controller;

import com.example.dto.response.DepreciationDeptResponse;
import com.example.mapping.DepreciationExcelExporter;
import com.example.mapping.DepreciationHistoryMapping;
import com.example.service.DepreciationHistoryService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@RestController
@RequestMapping("/api/depreciation/history")
@RequiredArgsConstructor
public class DepreciationHistoryController {
    private final DepreciationHistoryService depreciationHistoryService;
    private final DepreciationHistoryMapping depreciationHistoryMapping;
    //Tất cả thông tin khấu hao của phòng ban
    @GetMapping("/dept")
    public ResponseEntity getDepreciationValueAllDept(@RequestParam int year, @RequestParam(required = false) List<Long> ids){
        List<Object> records = new ArrayList<>();
        if(ids.size()==1&&ids.get(0)==0)
            records = depreciationHistoryService.getDepreciationByAllDept(year);
        else
            records = depreciationHistoryService.getDepreciationByDeptIds(year,ids);
        return new ResponseEntity(depreciationHistoryMapping.getDepreciationDeptResponse(records), HttpStatus.OK);
    }
    @GetMapping("/dept/export/excel")
    public void exportToExcel(HttpServletResponse response,@RequestParam int year, @RequestParam(required = false) List<Long> ids) throws IOException {
        List<Object> records = new ArrayList<>();
        if(ids.size()==1&&ids.get(0)==0)
            records = depreciationHistoryService.getDepreciationByAllDept(year);
        else
            records = depreciationHistoryService.getDepreciationByDeptIds(year,ids);
        List<DepreciationDeptResponse> responses = depreciationHistoryMapping.getDepreciationDeptResponse(records);

        response.setContentType("application/octet-stream");
        DateFormat dateFormatter = new SimpleDateFormat("yyyy-MM-dd_HH:mm:ss");
        String currentDateTime = dateFormatter.format(new Date());

        String headerKey = "Content-Disposition";
        String headerValue = "attachment; filename=depreciation_" + currentDateTime + ".xlsx";
        response.setHeader(headerKey, headerValue);
        DepreciationExcelExporter excelExporter = new DepreciationExcelExporter(responses);
        excelExporter.export(response);
    }
}
