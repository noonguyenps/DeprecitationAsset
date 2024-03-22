package com.example.mapping;

import com.example.dto.response.AssetResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;

@Component
@RequiredArgsConstructor
public class CommonMapping {
    public Double calculatorDepreciationPerMonth(AssetResponse asset, Double value, String lastDate) throws ParseException {
        //Lấy thông tin tài sản và thời gian
        Date lDate = new SimpleDateFormat("yyyy-MM-dd").parse(lastDate);
        Date eDate = new SimpleDateFormat("yyyy-MM-dd").parse(asset.getExpDate());
        int daysInLMonth = LocalDate.from(lDate.toInstant().atZone(ZoneId.systemDefault())).lengthOfMonth();
        int daysInEMonth = LocalDate.from(eDate.toInstant().atZone(ZoneId.systemDefault())).lengthOfMonth();
        //Tính số tháng còn lại cần khấu hao
        int amountMonth = (lDate.getDate() >= daysInLMonth/2 ? 0 : 1)
                + (11 - lDate.getMonth())
                + (eDate.getYear() - lDate.getYear() -1)*12
                + (eDate.getMonth())
                + (eDate.getDate() > daysInEMonth/2 ? 1: 0);
        //Kiểm tra tài sản có nâng cấp hay không
        if(asset.getUpdateId()!=null){
            return (asset.getPrice() - value)/Double.valueOf(amountMonth);
        }
        return asset.getPrice()/asset.getAmountOfYear();
    }
}
