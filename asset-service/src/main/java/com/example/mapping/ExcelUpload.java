package com.example.mapping;

import com.example.dto.request.AssetRequest;
import com.example.model.Asset;
import lombok.AllArgsConstructor;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
@AllArgsConstructor
@Component
public class ExcelUpload {
    private final AssetMapping assetMapping;
    public static boolean isValidExcelFile(MultipartFile file){
        return Objects.equals(file.getContentType(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" );
    }
    public List<Asset> getAssetsDataFromExcel(InputStream inputStream){
        List<Asset> assets = new ArrayList<>();
        try {
            XSSFWorkbook workbook = new XSSFWorkbook(inputStream);
            XSSFSheet sheet = workbook.getSheet("assets");
            int rowIndex =0;
            for (Row row : sheet){
                if (rowIndex ==0){
                    rowIndex++;
                    continue;
                }
                Iterator<Cell> cellIterator = row.iterator();
                int cellIndex = 0;
                AssetRequest assetRequest = new AssetRequest();
                assetRequest.setStatus(Long.valueOf(0));
                while (cellIterator.hasNext()){
                    Cell cell = cellIterator.next();
                    switch (cellIndex){
                        case 0 -> assetRequest.setAssetName(cell.getStringCellValue());
                        case 1 -> assetRequest.setAssetTypeId(Math.round(cell.getNumericCellValue()));
                        case 2 -> assetRequest.setPrice(cell.getNumericCellValue());
                        case 3 -> assetRequest.setSerial(cell.getStringCellValue());
                        case 4 -> assetRequest.setBrandId(Math.round(cell.getNumericCellValue()));
                        case 5 -> assetRequest.setStorageId(Math.round(cell.getNumericCellValue()));
                        case 6 -> assetRequest.setImage(cell.getStringCellValue());
                    }
                    cellIndex++;
                }
                assets.add(assetMapping.getAsset(assetRequest));
            }
        } catch (IOException e) {
            e.getStackTrace();
        }
        return assets;
    }
}
