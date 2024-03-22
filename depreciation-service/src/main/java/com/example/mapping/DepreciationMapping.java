package com.example.mapping;

import com.example.client.DepreciationServiceClient;
import com.example.dto.request.DepreciationRequest;
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
public class DepreciationMapping {
    private final DepreciationServiceClient depreciationServiceClient;
    private final DepreciationHistoryService depreciationHistoryService;
    private final CommonMapping commonMapping;

    //Hàm nhận request và thực hiện tính khấu hao và lưu lịch sử
    public Depreciation requestToEntity(DepreciationRequest depreciationRequest, Object object) throws ParseException {
        Depreciation depreciation = new Depreciation();
        depreciation.setActive(true);
        depreciation.setStatus(1);
        depreciation.setDeptId(depreciationRequest.getDeptId());
        depreciation.setAssetId(depreciationRequest.getAssetId());
        depreciation.setFromDate(new Date());
        AssetResponse assetResponse = depreciationServiceClient.fetchAsset(depreciation.getAssetId());
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
        depreciation.setAssetTypeId(assetResponse.getAssetTypeId());
        if(assetResponse.getExpDate() == null)
            depreciation.setExpDate(Date.from(LocalDate.now().plusMonths(assetResponse.getAmountOfYear()).atStartOfDay(ZoneId.systemDefault()).toInstant()));
        else
            depreciation.setExpDate(dateFormat.parse(assetResponse.getExpDate()));
        //Ngưng khấu hao đợt trước và gán khấu hao từ sau ngày kết thúc
        if(object != null){
            //Ngày khấu hao cuối cùng
            Date lDate = dateFormat.parse(((Object[])object)[1].toString());
            //Giá trị đã khấu hao
            Double valuePrev = Double.valueOf(((Object[])object)[2].toString());
            depreciation.setValuePerMonth(commonMapping.calculatorDepreciationPerMonth(assetResponse,valuePrev, dateFormat.format(lDate)));
            LocalDate localDate = lDate.toInstant().atZone(ZoneId.systemDefault()).toLocalDate().plusDays(1);
            depreciation.setFromDate(Date.from(localDate.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        }
        else depreciation.setValuePerMonth(assetResponse.getPrice()/assetResponse.getAmountOfYear());
        depreciation.setUserId(depreciationRequest.getUserId());
        depreciation.setCreateAt(new Date());
        return depreciation;
    }

    public Depreciation updateDepreciation(Depreciation depreciation) throws ParseException {
        AssetResponse assetResponse = depreciationServiceClient.fetchAsset(depreciation.getAssetId());
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
        //Tạo thông tin 4 ngày cơ bản
        //Ngày tạo thông tin khấu hao
        Date fDate = depreciation.getFromDate();
        //Ngày kết thúc dự kiến khấu hao
        Date eDate = depreciation.getExpDate();
        //Ngày hôm nay
        Date today = new Date();
        //Ngày đầu tháng này
        Date sDate = dateFormat.parse((today.getYear()+1900)+"-"+(today.getMonth()+1)+"-01");
        //Số ngày trong tháng này
        int dayInMonth = LocalDate.of(today.getYear()+1900,today.getMonth()+1,01).lengthOfMonth();
        //Số ngày trong tháng bắt đầu
        int dayInFMonth = LocalDate.of(fDate.getYear()+1900,fDate.getMonth()+1,01).lengthOfMonth();
        //Số ngày trong tháng kết thúc
        int dayInEMonth = LocalDate.of(eDate.getYear()+1900,eDate.getMonth()+1,01).lengthOfMonth();
        //Tính toán giá trị khấu hao lũy kế
        Double valuePrev = depreciationHistoryService.totalValueDepreciationByDepreciationId(depreciation.getId(),today.getMonth()+1,today.getYear()+1900);
        Double valueAssetPrev = depreciationHistoryService.totalValueDepreciationByAssetId(depreciation.getId(),today.getMonth()+1,today.getYear()+1900);
        valuePrev = valuePrev == null ? 0.0 : valuePrev;
        valueAssetPrev = valueAssetPrev == null ? 0.0 : valueAssetPrev;
        //Giá trị khấu hao trong tháng này
        Double valueInMonth = 0.0;
        //Giá trị còn lại của tài sản
        Double countValue = assetResponse.getPrice() - valueAssetPrev;
        //Các trường hợp và cách lưu lại lịch sử khấu hao
        int amountMonth = 0;
        // - TH1: TS đã kết thúc khấu hao
        if(eDate.before(sDate)){
            valueInMonth= 0.0;
            amountMonth = countMonth(fDate,eDate,dayInFMonth,dayInEMonth);
        }
        //Ngày đầu tháng < ngày kết thúc khấu hao
        else if(eDate.after(sDate)){
            //Ngày đầu tháng < ngày bắt đầu < ngày hôm nay < ngày kết thúc
            if(fDate.after(sDate)&&today.before(eDate)){
                valueInMonth = (Double.valueOf(today.getDate() - fDate.getDate()+1)/dayInMonth) * depreciation.getValuePerMonth();
                amountMonth = countMonth(fDate,today,dayInFMonth,dayInMonth);
                if(valueInMonth > countValue) valueInMonth = countValue;
            }//Ngày đầu tháng < ngày bắt đầu < ngày kết thúc < ngày hôm nay
            else if(sDate.before(fDate)&&eDate.before(today)){
                valueInMonth = (Double.valueOf(eDate.getDate() - fDate.getDate()+1)/dayInMonth) * depreciation.getValuePerMonth();
                amountMonth = 0;
                if(valueInMonth > countValue) valueInMonth = countValue;
            }//Ngày bắt đầu < ngày đầu tháng < ngày hôm nay < ngày kết thúc
            else if(fDate.before(sDate)&&today.before(eDate)){
                valueInMonth = (Double.valueOf(today.getDate() - sDate.getDate()+1)/dayInMonth) * depreciation.getValuePerMonth();
                amountMonth = countMonth(fDate,today,dayInFMonth,dayInMonth);
                if(valueInMonth > countValue) valueInMonth = countValue;
            }//Ngày bắt đầu < ngày đầu tháng < ngày kết thúc < ngày hôm nay
            else if(fDate.before(sDate)&&eDate.before(today)){
                valueInMonth = (Double.valueOf(eDate.getDate() - sDate.getDate()+1)/dayInMonth) * depreciation.getValuePerMonth();
                amountMonth = countMonth(fDate,eDate,dayInFMonth,dayInEMonth);
                if(valueInMonth > countValue) valueInMonth = countValue;
            }
        }
        depreciation.setAmountMonth(amountMonth);
        depreciation.setValueDepreciation(valuePrev+valueInMonth);
        depreciation.setStatus(2);
        if(today.after(eDate))
            depreciation.setToDate(eDate);
        else
            depreciation.setToDate(today);
        //Lưu thông tin lịch sử khấu hao
        DepreciationHistory depreciationHistory = new DepreciationHistory();
        depreciationHistory.setCreateAt(new Date());
        depreciationHistory.setMonth(today.getMonth()+1);
        depreciationHistory.setYear(today.getYear()+1900);
        depreciationHistory.setDepreciation(depreciation);
        depreciationHistory.setAssetId(depreciation.getAssetId());
        depreciationHistory.setAssetTypeId(depreciation.getAssetTypeId());
        depreciationHistory.setValue(valueInMonth);
        depreciationHistoryService.saveDepreciationHistory(depreciationHistory);
        return depreciation;
    }

    public int countMonth(Date sDate, Date eDate,int sMonth, int eMonth){
        int temp = (sDate.getDate() >= sMonth/2 ? 0 : 1)
                + (11 - sDate.getMonth())
                + (eDate.getYear() - sDate.getYear() -1)*12
                + (eDate.getMonth())
                + (eDate.getDate() > eMonth/2 ? 1: 0);
        return temp;
    }

}
