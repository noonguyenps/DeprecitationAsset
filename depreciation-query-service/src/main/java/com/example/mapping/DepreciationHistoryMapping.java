package com.example.mapping;

import com.example.client.DepreciationServiceClient;
import com.example.dto.response.*;
import com.example.model.Depreciation;
import com.example.model.DepreciationHistory;
import com.example.service.DepreciationHistoryService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.*;

@Component
@RequiredArgsConstructor
public class DepreciationHistoryMapping {
    private final DepreciationServiceClient depreciationServiceClient;
    private final DepreciationHistoryService depreciationHistoryService;

    public List<DepreciationDeptResponse> getDepreciationDeptResponse(List<Object> data){
        List<DepreciationDeptResponse> depreciationDeptResponses = new ArrayList<>();
        for(Object o : data) {
            //Lấy các thông tin từ DB
            Long deptId = Long.valueOf(((Object[]) o)[0].toString());
            Long assetTypeId = Long.valueOf(((Object[]) o)[1].toString());
            int month = Integer.valueOf(((Object[]) o)[2].toString());
            int year = Integer.valueOf(((Object[]) o)[3].toString());
            Double value = Double.valueOf(((Object[]) o)[4].toString());
            //Lấy giá trị dựa vào deptId
            Double valuePrev = depreciationHistoryService.getTotalValueByDeptId(deptId, year);
            // Gọp thông tin phòng ban
            DepreciationDeptResponse depreciationDeptResponse = depreciationDeptResponses.stream()
                    .filter(dept -> dept.getDeptId() == deptId)
                    .findFirst()
                    .orElse(null);
            if (depreciationDeptResponse == null) {
                depreciationDeptResponse = new DepreciationDeptResponse();
                DepartmentResponse departmentResponse = depreciationServiceClient.fetchDepartment(deptId);
                depreciationDeptResponse.setDeptId(departmentResponse.getId());
                depreciationDeptResponse.setDeptName(departmentResponse.getName());
                depreciationDeptResponse.setDepreciationPrev(valuePrev);
                depreciationDeptResponse.getMonths().put(String.valueOf(month), value);
                depreciationDeptResponses.add(depreciationDeptResponse);
            }else{
                if(depreciationDeptResponse.getMonths().get(String.valueOf(month))==null)
                    depreciationDeptResponse.getMonths().put(String.valueOf(month), value);
                else
                    depreciationDeptResponse.getMonths().put(String.valueOf(month), value + depreciationDeptResponse.getMonths().get(String.valueOf(month)));
            }
            //Tính tổng các giá trị của dept
            if(month == 1 || month == 2 || month == 3 )
                depreciationDeptResponse.setTotal1(value+depreciationDeptResponse.getTotal1());
            else if(month == 4 || month == 5 || month == 6)
                depreciationDeptResponse.setTotal2(value+depreciationDeptResponse.getTotal2());
            else if(month == 7 || month == 8 || month == 9)
                depreciationDeptResponse.setTotal3(value+depreciationDeptResponse.getTotal3());
            else
                depreciationDeptResponse.setTotal4(value+depreciationDeptResponse.getTotal4());
            depreciationDeptResponse.setTotalPrice(value+depreciationDeptResponse.getTotalPrice());
            //Gọp thông tin Loại tài sản
            List<AssetType> assetTypes = depreciationDeptResponse.getAssetTypes();
            AssetType assetType = assetTypes.stream()
                        .filter(type -> type.getTypeId() == assetTypeId)
                        .findFirst()
                        .orElse(null);
            //AssetType chưa tồn tại thực hiện thêm mới
            if(assetType == null) {
                assetType = new AssetType();
                assetType.setTypeId(assetTypeId);
                Double valueTypePrev = depreciationHistoryService.getTotalValueByDeptIdAndAssetType(deptId,assetTypeId, year);
                AssetTypeResponse assetTypeResponse = depreciationServiceClient.fetchAssetType(assetTypeId);
                assetType.setTypeName(assetTypeResponse.getAssetName());
                assetType.setDepreciationPrev(valueTypePrev);
                assetType.setTotalPrice(value);
                assetType.getMonths().put(String.valueOf(month),value);
                assetTypes.add(assetType);
            }else {
                assetType.setTotalPrice(value+assetType.getTotalPrice());
                assetType.getMonths().put(String.valueOf(month),value);
            }
            //Tính tổng các giá trị của assetType
            if(month == 1 || month == 2 || month == 3 )
                assetType.setTotal1(value+assetType.getTotal1());
            else if(month == 4 || month == 5 || month == 6)
                assetType.setTotal2(value+assetType.getTotal2());
            else if(month == 7 || month == 8 || month == 9)
                assetType.setTotal3(value+assetType.getTotal3());
            else
                assetType.setTotal4(value+assetType.getTotal4());
        }
        return depreciationDeptResponses;
    }
}
