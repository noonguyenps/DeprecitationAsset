package com.example.mapping;

import com.example.dto.response.AssetType;
import com.example.dto.response.DepreciationDeptResponse;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

public class DepreciationExcelExporter {
    private XSSFWorkbook workbook;
    private XSSFSheet sheet;
    private List<DepreciationDeptResponse> list;
    public static final int COLUMN_INDEX_TYPE       = 0;
    public static final int COLUMN_INDEX_PREV       = 1;
    public static final int COLUMN_INDEX_MONTH_1    = 2;
    public static final int COLUMN_INDEX_MONTH_2    = 3;
    public static final int COLUMN_INDEX_MONTH_3    = 4;
    public static final int COLUMN_INDEX_QUARTER_1  = 5;
    public static final int COLUMN_INDEX_MONTH_4    = 6;
    public static final int COLUMN_INDEX_MONTH_5    = 7;
    public static final int COLUMN_INDEX_MONTH_6    = 8;
    public static final int COLUMN_INDEX_QUARTER_2  = 9;
    public static final int COLUMN_INDEX_MONTH_7    = 10;
    public static final int COLUMN_INDEX_MONTH_8    = 11;
    public static final int COLUMN_INDEX_MONTH_9    = 12;
    public static final int COLUMN_INDEX_QUARTER_3  = 13;
    public static final int COLUMN_INDEX_MONTH_10   = 14;
    public static final int COLUMN_INDEX_MONTH_11   = 15;
    public static final int COLUMN_INDEX_MONTH_12   = 16;
    public static final int COLUMN_INDEX_QUARTER_4  = 17;
    public static final int COLUMN_INDEX_TOTAL_PRE  = 18;
    public static final int COLUMN_INDEX_TOTAL      = 19;

    public DepreciationExcelExporter(List<DepreciationDeptResponse> list) {
        this.list = list;
        workbook = new XSSFWorkbook();
    }

    private static CellStyle createStyleForHeader(Sheet sheet) {
        // Create font
        Font font = sheet.getWorkbook().createFont();
        font.setFontName("Times New Roman");
        font.setBold(true);
        font.setFontHeightInPoints((short) 14); // font size
        font.setColor(IndexedColors.BLACK.getIndex()); // text color

        // Create CellStyle
        CellStyle cellStyle = sheet.getWorkbook().createCellStyle();
        cellStyle.setFont(font);
        cellStyle.setFillForegroundColor(IndexedColors.LIGHT_YELLOW.getIndex());
        cellStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);
        return cellStyle;
    }

    private static CellStyle createStyleDept(Sheet sheet) {
        // Create font
        Font font = sheet.getWorkbook().createFont();
        font.setColor(IndexedColors.RED.getIndex()); // text color
        // Create CellStyle
        CellStyle cellStyle = sheet.getWorkbook().createCellStyle();
        cellStyle.setFont(font);
        return cellStyle;
    }

    private static CellStyle createStyleType(Sheet sheet) {
        // Create font
        Font font = sheet.getWorkbook().createFont();
        font.setColor(IndexedColors.BLACK.getIndex()); // text color
        // Create CellStyle
        CellStyle cellStyle = sheet.getWorkbook().createCellStyle();
        cellStyle.setFont(font);
        return cellStyle;
    }

    private static void writeHeader(Sheet sheet, int rowIndex) {
        // create CellStyle
        CellStyle cellStyle = createStyleForHeader(sheet);

        // Create row
        Row row = sheet.createRow(rowIndex);

        // Create cells
        Cell cell = row.createCell(COLUMN_INDEX_TYPE);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Loại tài sản");

        cell = row.createCell(COLUMN_INDEX_PREV);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Lũy kế đầu năm");

        cell = row.createCell(COLUMN_INDEX_MONTH_1);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Giá trị KH tháng 1");

        cell = row.createCell(COLUMN_INDEX_MONTH_2);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Giá trị KH tháng 2");

        cell = row.createCell(COLUMN_INDEX_MONTH_3);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Giá trị KH tháng 3");

        cell = row.createCell(COLUMN_INDEX_QUARTER_1);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Giá trị KH quý I");

        cell = row.createCell(COLUMN_INDEX_MONTH_4);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Giá trị KH tháng 4");

        cell = row.createCell(COLUMN_INDEX_MONTH_5);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Giá trị KH tháng 5");

        cell = row.createCell(COLUMN_INDEX_MONTH_6);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Giá trị KH tháng 6");

        cell = row.createCell(COLUMN_INDEX_QUARTER_2);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Giá trị KH quý II");

        cell = row.createCell(COLUMN_INDEX_MONTH_7);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Giá trị KH tháng 7");

        cell = row.createCell(COLUMN_INDEX_MONTH_8);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Giá trị KH tháng 8");

        cell = row.createCell(COLUMN_INDEX_MONTH_9);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Giá trị KH tháng 9");

        cell = row.createCell(COLUMN_INDEX_QUARTER_3);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Giá trị KH quý III");

        cell = row.createCell(COLUMN_INDEX_MONTH_10);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Giá trị KH tháng 10");

        cell = row.createCell(COLUMN_INDEX_MONTH_11);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Giá trị KH tháng 11");

        cell = row.createCell(COLUMN_INDEX_MONTH_12);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Giá trị KH tháng 12");

        cell = row.createCell(COLUMN_INDEX_QUARTER_4);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Giá trị KH quý IV");

        cell = row.createCell(COLUMN_INDEX_TOTAL_PRE);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Tổng KH năm");

        cell = row.createCell(COLUMN_INDEX_TOTAL);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Giá trị lũy kế cuối năm");

        for(int i =0 ; i<20;i++)
            sheet.autoSizeColumn(i);
    }
    private void writeData(List<DepreciationDeptResponse> list, Sheet sheet) {
        int i = 1;
        for(DepreciationDeptResponse response : list){
            Row row = sheet.createRow(i);
            CellStyle style = createStyleDept(sheet);
            createCell(style,row, response.getDeptName(), response.getDepreciationPrev(),
                    response.getMonths().get("1")!=null?response.getMonths().get("1"):0.0,
                    response.getMonths().get("2")!=null?response.getMonths().get("2"):0.0,
                    response.getMonths().get("3")!=null?response.getMonths().get("3"):0.0,
                    response.getTotal1(),
                    response.getMonths().get("4")!=null?response.getMonths().get("4"):0.0,
                    response.getMonths().get("5")!=null?response.getMonths().get("5"):0.0,
                    response.getMonths().get("6")!=null?response.getMonths().get("6"):0.0,
                    response.getTotal2(),
                    response.getMonths().get("7")!=null?response.getMonths().get("7"):0.0,
                    response.getMonths().get("8")!=null?response.getMonths().get("8"):0.0,
                    response.getMonths().get("9")!=null?response.getMonths().get("9"):0.0,
                    response.getTotal3(),
                    response.getMonths().get("10")!=null?response.getMonths().get("10"):0.0,
                    response.getMonths().get("11")!=null?response.getMonths().get("11"):0.0,
                    response.getMonths().get("12")!=null?response.getMonths().get("12"):0.0,
                    response.getTotal4(),
                    response.getTotalPrice());
            i++;
            for(AssetType assetType : response.getAssetTypes()){
                Row childernRow = sheet.createRow(i);
                CellStyle styleType = createStyleType(sheet);
                createCell(styleType,childernRow, assetType.getTypeName(), assetType.getDepreciationPrev(),
                        assetType.getMonths().get("1")!=null?assetType.getMonths().get("1"):0.0,
                        assetType.getMonths().get("2")!=null?assetType.getMonths().get("2"):0.0,
                        assetType.getMonths().get("3")!=null?assetType.getMonths().get("3"):0.0,
                        assetType.getTotal1(),
                        assetType.getMonths().get("4")!=null?assetType.getMonths().get("4"):0.0,
                        assetType.getMonths().get("5")!=null?assetType.getMonths().get("5"):0.0,
                        assetType.getMonths().get("6")!=null?assetType.getMonths().get("6"):0.0,
                        assetType.getTotal2(),
                        assetType.getMonths().get("7")!=null?assetType.getMonths().get("7"):0.0,
                        assetType.getMonths().get("8")!=null?assetType.getMonths().get("8"):0.0,
                        assetType.getMonths().get("9")!=null?assetType.getMonths().get("9"):0.0,
                        assetType.getTotal3(),
                        assetType.getMonths().get("10")!=null?assetType.getMonths().get("10"):0.0,
                        assetType.getMonths().get("11")!=null?assetType.getMonths().get("11"):0.0,
                        assetType.getMonths().get("12")!=null?assetType.getMonths().get("12"):0.0,
                        assetType.getTotal4(),
                        assetType.getTotalPrice());
                i++;
            }
        }
    }

    private void createCell(CellStyle cellStyleFormatNumber,Row row, String col0,Double col1,Double col2, Double col3, Double col4, Double col5, Double col6,
                            Double col7, Double col8, Double col9, Double col10, Double col11, Double col12, Double col13, Double col14,
                            Double col15, Double col16, Double col17, Double col18) {
        Cell cell = row.createCell(COLUMN_INDEX_TYPE);
        cell.setCellValue(col0);
        cell.setCellStyle(cellStyleFormatNumber);
        short format = (short)BuiltinFormats.getBuiltinFormat("#,##0");
        cellStyleFormatNumber.setDataFormat(format);
        cell = row.createCell(COLUMN_INDEX_PREV);
        cell.setCellValue(col1);
        cell.setCellStyle(cellStyleFormatNumber);

        cell = row.createCell(COLUMN_INDEX_MONTH_1);
        cell.setCellValue(col2);
        cell.setCellStyle(cellStyleFormatNumber);

        cell = row.createCell(COLUMN_INDEX_MONTH_2);
        cell.setCellValue(col3);
        cell.setCellStyle(cellStyleFormatNumber);

        cell = row.createCell(COLUMN_INDEX_MONTH_3);
        cell.setCellValue(col4);
        cell.setCellStyle(cellStyleFormatNumber);

        cell = row.createCell(COLUMN_INDEX_QUARTER_1);
        cell.setCellValue(col5);
        cell.setCellStyle(cellStyleFormatNumber);

        cell = row.createCell(COLUMN_INDEX_MONTH_4);
        cell.setCellValue(col6);
        cell.setCellStyle(cellStyleFormatNumber);

        cell = row.createCell(COLUMN_INDEX_MONTH_5);
        cell.setCellValue(col7);
        cell.setCellStyle(cellStyleFormatNumber);

        cell = row.createCell(COLUMN_INDEX_MONTH_6);
        cell.setCellValue(col8);
        cell.setCellStyle(cellStyleFormatNumber);

        cell = row.createCell(COLUMN_INDEX_QUARTER_2);
        cell.setCellValue(col9);
        cell.setCellStyle(cellStyleFormatNumber);

        cell = row.createCell(COLUMN_INDEX_MONTH_7);
        cell.setCellValue(col10);
        cell.setCellStyle(cellStyleFormatNumber);

        cell = row.createCell(COLUMN_INDEX_MONTH_8);
        cell.setCellValue(col11);
        cell.setCellStyle(cellStyleFormatNumber);

        cell = row.createCell(COLUMN_INDEX_MONTH_9);
        cell.setCellValue(col12);
        cell.setCellStyle(cellStyleFormatNumber);

        cell = row.createCell(COLUMN_INDEX_QUARTER_3);
        cell.setCellValue(col13);
        cell.setCellStyle(cellStyleFormatNumber);

        cell = row.createCell(COLUMN_INDEX_MONTH_10);
        cell.setCellValue(col14);
        cell.setCellStyle(cellStyleFormatNumber);

        cell = row.createCell(COLUMN_INDEX_MONTH_11);
        cell.setCellValue(col15);
        cell.setCellStyle(cellStyleFormatNumber);

        cell = row.createCell(COLUMN_INDEX_MONTH_12);
        cell.setCellValue(col16);
        cell.setCellStyle(cellStyleFormatNumber);

        cell = row.createCell(COLUMN_INDEX_QUARTER_4);
        cell.setCellValue(col17);
        cell.setCellStyle(cellStyleFormatNumber);

        cell = row.createCell(COLUMN_INDEX_TOTAL_PRE);
        cell.setCellValue(col18);
        cell.setCellStyle(cellStyleFormatNumber);

        cell = row.createCell(COLUMN_INDEX_TOTAL);
        cell.setCellValue(col1+col18);
        cell.setCellStyle(cellStyleFormatNumber);
    }

    public void export(HttpServletResponse response) throws IOException {
        sheet = workbook.createSheet("Depreciation");
        writeHeader(sheet,0);
        writeData(list,sheet);
        ServletOutputStream outputStream = response.getOutputStream();
        workbook.write(outputStream);
        workbook.close();
        outputStream.close();
    }
}
