package com.example.tasks;

import com.example.client.DepreciationServiceClient;
import com.example.dto.response.AssetResponse;
import com.example.model.Depreciation;
import com.example.model.DepreciationHistory;
import com.example.service.DepreciationHistoryService;
import com.example.service.DepreciationService;
import lombok.AllArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.util.Date;
import java.util.List;

@Component
@AllArgsConstructor
public class DepreciationHistoryTask {
    private final DepreciationService depreciationService;
    private final DepreciationHistoryService depreciationHistoryService;
    private final DepreciationServiceClient depreciationServiceClient;

    //Hàm tính lịch sử khấu hao được khởi tạo và chạy vào mỗi đầu tháng
    @Scheduled(cron = "00 00 00 1 * ?")
    public void calculateDepreciationPerMonth() throws ParseException {
        //Khởi tạo ngày đầu tháng và cuối tháng
        LocalDate today = LocalDate.now().minusDays(1);
        Date fromDate = new SimpleDateFormat("yyyy-MM-dd").parse(today.getYear()+"-"+today.getMonthValue()+"-01");
        Date toDate = new SimpleDateFormat("yyyy-MM-dd").parse(today.getYear()+"-"+today.getMonthValue()+"-"+today.lengthOfMonth());
        //Tìm danh sách các khấu hao còn đang chạy và các khấu hao được tạo trong tháng
        List<Depreciation> depreciationList = depreciationService.getDepreciationByFromDateAndToDate(fromDate, toDate);
        for(Depreciation depreciation: depreciationList){
            DepreciationHistory depreciationHistory = new DepreciationHistory();
            depreciationHistory.setCreateAt(new Date());
            depreciationHistory.setMonth(today.getMonthValue());
            depreciationHistory.setYear(today.getYear());
            depreciationHistory.setDepreciation(depreciation);
            depreciationHistory.setAssetId(depreciation.getAssetId());
            depreciationHistory.setAssetTypeId(depreciation.getAssetTypeId());
            //Tính giá trị khấu hao
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
            //Kiểm tra xem đã là tháng cuối chưa
            if(depreciation.getExpDate().after(fromDate)&&depreciation.getExpDate().before(toDate)){
                //Tính khấu hao còn lại
                AssetResponse assetResponse = depreciationServiceClient.fetchAsset(depreciation.getAssetId());
                depreciationHistory.setValue(assetResponse.getPrice()-depreciationHistoryService.totalValueDepreciationByAssetId(depreciation.getAssetId()));
            }else if(depreciation.getFromDate().before(fromDate))
                //Tính khấu hao đầy đủ theo một tháng
                depreciationHistory.setValue(depreciation.getValuePerMonth());
            else
                //Nếu số ngày trong tháng lẻ thì tính theo thời gian
                depreciationHistory.setValue((Double.valueOf(toDate.getDate()-depreciation.getFromDate().getDate()+1)/today.lengthOfMonth())*depreciation.getValuePerMonth());
            depreciationHistoryService.saveDepreciationHistory(depreciationHistory);
        }
    }
    //Hàm tính thủ công
    public void calculateDepreciationPerMonthTest(String text) throws ParseException {
        //Khởi tạo ngày đầu tháng và cuối tháng
        LocalDate today = LocalDate.parse(text);
        Date fromDate = new SimpleDateFormat("yyyy-MM-dd").parse(today.getYear()+"-"+today.getMonthValue()+"-01");
        Date toDate = new SimpleDateFormat("yyyy-MM-dd").parse(today.getYear()+"-"+today.getMonthValue()+"-"+today.lengthOfMonth());
        //Tìm danh sách các khấu hao còn đang chạy và các khấu hao được tạo trong tháng
        List<Depreciation> depreciationList = depreciationService.getDepreciationByFromDateAndToDate(fromDate, toDate);
        for(Depreciation depreciation: depreciationList){
            DepreciationHistory depreciationHistory = new DepreciationHistory();
            depreciationHistory.setCreateAt(new Date());
            depreciationHistory.setMonth(today.getMonthValue());
            depreciationHistory.setYear(today.getYear());
            depreciationHistory.setDepreciation(depreciation);
            depreciationHistory.setAssetId(depreciation.getAssetId());
            depreciationHistory.setAssetTypeId(depreciation.getAssetTypeId());
            //Tính giá trị khấu hao
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
            //Kiểm tra xem đã là tháng cuối chưa
            if(depreciation.getExpDate().after(fromDate)&&depreciation.getExpDate().before(toDate)){
                //Tính khấu hao còn lại
                AssetResponse assetResponse = depreciationServiceClient.fetchAsset(depreciation.getAssetId());
                depreciationHistory.setValue(assetResponse.getPrice()-depreciationHistoryService.totalValueDepreciationByAssetId(depreciation.getAssetId()));
            }else if(depreciation.getFromDate().before(fromDate))
                //Tính khấu hao đầy đủ theo một tháng
                depreciationHistory.setValue(depreciation.getValuePerMonth());
            else
                //Nếu số ngày trong tháng lẻ thì tính theo thời gian
                depreciationHistory.setValue((Double.valueOf(toDate.getDate()-depreciation.getFromDate().getDate()+1)/today.lengthOfMonth())*depreciation.getValuePerMonth());
            depreciationHistoryService.saveDepreciationHistory(depreciationHistory);

        }
    }
}
