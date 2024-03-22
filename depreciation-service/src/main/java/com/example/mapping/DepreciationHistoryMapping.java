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
    private final DepreciationHistoryService depreciationHistoryService;
    public void addDepreciationHistory(Depreciation depreciation){
        //Kéo lịch sử khấu hao đến cuối tháng
        Date today = new Date();
        Date lDate =  depreciation.getFromDate();
        int dayInMonth = lDate.toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDate().lengthOfMonth();
        //Nếu đã hết khấu hao thì chỉ cho phép tính khấu hao đến ngày kết thúc
        if(today.after(depreciation.getExpDate()))
            today = depreciation.getExpDate();
        //Nếu thời gian nhận tài sản bị kéo sang các tháng sau thì thực hiện kéo lịch sử khấu hao
        if((today.getMonth()>lDate.getMonth()&&today.getYear()==lDate.getYear())||today.getYear()>lDate.getYear()){
            //Kéo đến cuối tháng khi thu hồi tài sản
            DepreciationHistory depreciationHistory = new DepreciationHistory();
            depreciationHistory.setCreateAt(new Date());
            depreciationHistory.setMonth(lDate.getMonth()+1);
            depreciationHistory.setYear(lDate.getYear()+1900);
            depreciationHistory.setDepreciation(depreciation);
            depreciationHistory.setAssetId(depreciation.getAssetId());
            depreciationHistory.setAssetTypeId(depreciation.getAssetTypeId());
            depreciationHistory.setValue((Double.valueOf(dayInMonth-lDate.getDate())/dayInMonth)*depreciation.getValuePerMonth());
            depreciationHistoryService.saveDepreciationHistory(depreciationHistory);
            //Nếu thời gian sử dụng bị kéo sau x tháng
            int month = depreciation.getFromDate().getMonth()+1;
            for (int i = depreciation.getFromDate().getYear(); i <=today.getYear(); i++){
                for(int j = month; j<12;j++){
                    if(j==today.getMonth()&&i==today.getYear())
                        break;
                    depreciationHistory = new DepreciationHistory();
                    depreciationHistory.setCreateAt(new Date());
                    depreciationHistory.setMonth(j+1);
                    depreciationHistory.setYear(i+1900);
                    depreciationHistory.setDepreciation(depreciation);
                    depreciationHistory.setAssetId(depreciation.getAssetId());
                    depreciationHistory.setAssetTypeId(depreciation.getAssetTypeId());
                    depreciationHistory.setValue(depreciation.getValuePerMonth());
                    depreciationHistoryService.saveDepreciationHistory(depreciationHistory);
                }
            }
        }
    }
}
