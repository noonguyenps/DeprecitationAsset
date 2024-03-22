package com.example.mapping;

import com.example.client.DepreciationServiceClient;
import com.example.dto.request.DepreciationRequest;
import com.example.dto.response.AssetResponse;
import com.example.dto.response.DepreciationByAssetResponse;
import com.example.dto.response.DepreciationHistoryByDepreciation;
import com.example.dto.response.UserResponse;
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

    public DepreciationByAssetResponse getDepreciationAssetResponse(Long assetId, List<Depreciation> lDepreciation) throws ParseException {
        DepreciationByAssetResponse depreciationByAssetResponse = new DepreciationByAssetResponse();
        LocalDate localDate = LocalDate.now();
        int amountDate = 0;
        Double valuePre = 0.0;
        Double valueTemp = depreciationHistoryService.totalValueDepreciationByAssetId(assetId,new Date().getMonth()+1, new Date().getYear()+1900);
        Double valuePrev = valueTemp == null ? 0.0 : valueTemp;
        //Khởi tạo ngày đầu tháng và hôm nay
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
        Date sDate = dateFormat.parse(localDate.getYear()+"-"+localDate.getMonthValue()+"-01");
        Date today = new Date();
        AssetResponse assetResponse = depreciationServiceClient.fetchAsset(assetId);
        Date expDate = dateFormat.parse(assetResponse.getExpDate());
        List<DepreciationByAssetResponse.DepreciationAssetHistory> list = new ArrayList<>();
        for(Depreciation depreciation: lDepreciation){
            List<DepreciationHistoryByDepreciation> depreciationList = getDepreciationHistoryByDepreciation(depreciation);
            UserResponse userResponse = depreciationServiceClient.fetchUser(depreciation.getUserId());
            Double value = 0.0;
            if(depreciation.getToDate() == null){
                Object object = depreciationHistoryService.getValueHistoryByDepreciation(localDate.getMonthValue(), localDate.getYear(), depreciation.getId());
                value += object != null ? Double.valueOf(((Object[])object)[1].toString()): 0.0;
                //Kiểm tra tài sản còn khấu hao hay không
                if(expDate.after(sDate)&&expDate.before(today)){
                    //Khấu hao được tính từ ngày đầu đến ngày kết thúc
                    amountDate = expDate.getDate()-sDate.getDate()+1;
                    valuePre = (Double.valueOf(amountDate)/localDate.lengthOfMonth())*depreciation.getValuePerMonth();
                }else if(expDate.before(sDate)){
                    //Khấu hao đã kết thúc
                    valuePre = 0.0;
                    amountDate = 0;
                }else if(depreciation.getFromDate().after(sDate)){
                    //Khấu hao từ ngày nhập đến hôm nay
                    amountDate = today.getDate() - depreciation.getFromDate().getDate() + 1;
                    valuePre = (Double.valueOf(amountDate)/localDate.lengthOfMonth())*depreciation.getValuePerMonth();
                }else{
                    //Khấu hao vẫn chưa hết
                    amountDate = today.getDate()-sDate.getDate()+1;
                    valuePre = (Double.valueOf(amountDate)/localDate.lengthOfMonth())*depreciation.getValuePerMonth();
                }
                value+=valuePre;
            }
            String toDate;
            if(depreciation.getToDate()==null&&depreciation.getExpDate().before(sDate))
                toDate = "Tài sản đã kết thúc khấu hao";
            else if(depreciation.getToDate()==null)
                toDate = "Đang sử dụng";
            else
                toDate = dateFormat.format(depreciation.getToDate());
            list.add(new DepreciationByAssetResponse.DepreciationAssetHistory(depreciation.getId()
                    ,userResponse
                    ,dateFormat.format(depreciation.getFromDate())
                    ,toDate
                    ,depreciation.getValueDepreciation()==null?value: depreciation.getValueDepreciation()
                    ,0
                    ,depreciationList));
        }
        //Tạo thông tin Response
        depreciationByAssetResponse.setValuePre(valuePre);
        depreciationByAssetResponse.setValuePrev(valuePrev);
        depreciationByAssetResponse.setLengthOfMonth(localDate.lengthOfMonth());
        depreciationByAssetResponse.setAmountDate(amountDate);
        depreciationByAssetResponse.setAmountMonth(assetResponse.getAmountOfYear());
        depreciationByAssetResponse.setAssetId(assetId);
        depreciationByAssetResponse.setAssetName(assetResponse.getAssetName());
        depreciationByAssetResponse.setPrice(assetResponse.getPrice());
        depreciationByAssetResponse.setFromDate(assetResponse.getDateUsed());
        depreciationByAssetResponse.setExpDate(assetResponse.getExpDate());
        depreciationByAssetResponse.setTotalValue(assetResponse.getPrice()-valuePre-valuePrev);
        depreciationByAssetResponse.setChangePrice("Không");
        depreciationByAssetResponse.setListDepreciationAssetHistory(list);
        return depreciationByAssetResponse;
    }
    public List<DepreciationHistoryByDepreciation> getDepreciationHistoryByDepreciation(Depreciation depreciation){
        List<DepreciationHistoryByDepreciation> list = new ArrayList<>();
        List<DepreciationHistory> depreciationHistories = depreciationHistoryService.findByDepreciation(depreciation);
        for(DepreciationHistory depreciationHistory : depreciationHistories){
            LocalDate localDate = LocalDate.of(depreciationHistory.getYear(),depreciationHistory.getMonth(),15);
            DepreciationHistoryByDepreciation depreciationHistoryByDepreciation  = list.stream()
                    .filter(o -> o.getYear() == depreciationHistory.getYear())
                    .findFirst()
                    .orElse(null);
            if(depreciationHistoryByDepreciation == null){
                depreciationHistoryByDepreciation = new DepreciationHistoryByDepreciation();
                depreciationHistoryByDepreciation.setYear(depreciationHistory.getYear());
                Map<String,Double> months = new HashMap<>();
                Map<String,String> dates = new HashMap<>();
                months.put(String.valueOf(depreciationHistory.getMonth()),depreciationHistory.getValue());
                Double result = (depreciationHistory.getValue()/depreciation.getValuePerMonth())*localDate.lengthOfMonth();
                dates.put(String.valueOf(depreciationHistory.getMonth()),Math.round(result)+"/"+localDate.lengthOfMonth());
                depreciationHistoryByDepreciation.setMonths(months);
                depreciationHistoryByDepreciation.setDates(dates);
                list.add(depreciationHistoryByDepreciation);
            }else{
                Map<String,Double> months = depreciationHistoryByDepreciation.getMonths();
                Map<String,String> dates = depreciationHistoryByDepreciation.getDates();
                months.put(String.valueOf(depreciationHistory.getMonth()),depreciationHistory.getValue());
                Double result = (depreciationHistory.getValue()/depreciation.getValuePerMonth())*localDate.lengthOfMonth();
                dates.put(String.valueOf(depreciationHistory.getMonth()),Math.round(result)+"/"+localDate.lengthOfMonth());
                depreciationHistoryByDepreciation.setMonths(months);
            }
        }
        return list;
    }

}
