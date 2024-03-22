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
//    public Double calculatorDepreciation(AssetResponse asset, String fromDate, String toDate, Double value, String lastDate) throws ParseException {
//        //Lấy thông tin tài sản và thời gian
//        Date fDate = new SimpleDateFormat("yyyy-MM-dd").parse(fromDate);
//        Date tDate = new SimpleDateFormat("yyyy-MM-dd").parse(toDate);
//        Date lDate = new SimpleDateFormat("yyyy-MM-dd").parse(lastDate);
//        Date eDate = new SimpleDateFormat("yyyy-MM-dd").parse(asset.getExpDate());
//        int daysInMonth = LocalDate.from(fDate.toInstant().atZone(ZoneId.systemDefault())).lengthOfMonth();
//        int daysInLMonth = LocalDate.from(lDate.toInstant().atZone(ZoneId.systemDefault())).lengthOfMonth();
//        int daysInEMonth = LocalDate.from(eDate.toInstant().atZone(ZoneId.systemDefault())).lengthOfMonth();
//        int amountMonth = (lDate.getDate() >= daysInLMonth/2 ? 0 : 1)
//                + (11 - lDate.getMonth())
//                + (eDate.getYear() - lDate.getYear() -1)*12
//                + (eDate.getMonth())
//                + (eDate.getDate() > daysInEMonth/2 ? 1: 0);
//        //Kiểm tra thông tin là tháng cuối hay chưa
//        if(eDate.getMonth()==fDate.getMonth()&&eDate.getYear()==fDate.getYear())
//            return depreciation3(asset.getPrice(),value,amountMonth);
//        //Kiểm tra tài sản có nâng cấp hay không
//        if(asset.getUpdateId()!=null){
//            return depreciation2(asset.getPrice(),value,Long.valueOf(amountMonth),tDate.getDate()-fDate.getDate()+1,daysInMonth);
//        }
//        return depreciation1(asset.getPrice(), asset.getAmountOfYear(),tDate.getDate()-fDate.getDate()+1,daysInMonth);
//    }

//    //Công thức tính khấu hao 1
//    public Double depreciation1(Double price, int amountMonth, int days, int amountDay) {
//        return (price/amountMonth)*(Double.valueOf(days)/amountDay);
//    }
//
//    //Công thức tính khấu hao 2
//    public Double depreciation2(Double price, Double valueUsed, Long amountMonth, int days, int amountDay){
//        return ((price - valueUsed)/amountMonth)*(Double.valueOf(days)/amountDay);
//    }
//    //Công thức tính khấu hao 3
//    public Double depreciation3(Double price, Double valueUsed,int amountMonth){
//        return price - valueUsed - (amountMonth-1)*((price-valueUsed)/amountMonth);
//    }
}
