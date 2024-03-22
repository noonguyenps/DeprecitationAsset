package com.example.controller;

import com.example.dto.request.AssetRequest;
import com.example.dto.request.DeliveryRequest;
import com.example.dto.request.UpdateHistoryRequest;
import com.example.dto.response.AssetResponse;
import com.example.dto.response.Response;
import com.example.mapping.AssetMapping;
import com.example.model.Asset;
import com.example.model.UpdateHistory;
import com.example.service.AssetGroupService;
import com.example.service.AssetService;
import com.example.service.AssetTypeService;
import com.example.service.UpdateHistoryService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

@RestController
@RequestMapping("/api/asset")
@RequiredArgsConstructor
public class AssetController {
    @Autowired
    AssetService assetService;
    @Autowired
    AssetMapping assetMapping;
    @Autowired
    AssetTypeService assetTypeService;
    @Autowired
    UpdateHistoryService updateHistoryService;
    @Autowired
    AssetGroupService assetGroupService;

    //API GET ASSET DATA V0
    // Lấy tất cả thông tin tài sản trong DB
    @GetMapping("")
    public ResponseEntity<Response> getAllAsset(@RequestParam(defaultValue = "0") int page,
                                                @RequestParam(defaultValue = "10") int size,
                                                @RequestParam(defaultValue = "assetId") String sort){
        Map<String,Object> data = new HashMap<>();
        List<AssetResponse> assetResponses = new ArrayList<>();
        Page<Asset> assets = assetService.getAssets(page,size,sort);
        for(Asset asset: assets) assetResponses.add(assetMapping.getAssetResponse(asset));
        data.put("assets",assetResponses);
        data.put("totalPage",assets.getTotalPages());
        return new ResponseEntity<>(new Response("Danh sách tài sản",data),HttpStatus.OK);
    }
    //Lấy thông tin tái sản theo Mã tài sản
    @GetMapping("/{id}")
    public ResponseEntity<Response> getAssetById(@PathVariable Long id){
        Map<String,Object> data = new HashMap<>();
        data.put("asset",assetMapping.getAssetResponse(assetService.findAssetById(id)));
        return new ResponseEntity<>(new Response("Thông tin tài sản",data),HttpStatus.OK);
    }
    //Lấy thông tin tài sản theo Mã tái sản
    @GetMapping("/v1/{id}")
    public ResponseEntity getAssetByIdv1(@PathVariable Long id){
        return new ResponseEntity(assetMapping.getAssetResponse(assetService.findAssetById(id)),HttpStatus.OK);
    }
    //Lấy danh sách loại tài sản
    @GetMapping("/type")
    public ResponseEntity getAllAssetType(){
        return new ResponseEntity(assetTypeService.getAllAsset(), HttpStatus.OK);
    }
    //Lấy thông tin loại tài sản theo Mã loại tài sản
    @GetMapping("/type/{id}")
    public ResponseEntity getAllAssetTypeById(@PathVariable Long id){
        return new ResponseEntity(assetTypeService.findAssetTypeById(id), HttpStatus.OK);
    }
    //Lấy danh sách tài sản theo mã phòng ban
    @GetMapping("/dept/{id}")
    public ResponseEntity<Response> getAssetByDeptId(@PathVariable Long id,
                                                     @RequestParam(defaultValue = "0") int page,
                                                     @RequestParam(defaultValue = "10") int size,
                                                     @RequestParam(defaultValue = "assetId") String sort){
        Map<String,Object> data = new HashMap<>();
        Page<Asset> assets = assetService.findAssetByDeptId(id,page,size,sort);
        List<AssetResponse> assetResponses = new ArrayList<>();
        for(Asset asset: assets) assetResponses.add(assetMapping.getAssetResponse(asset));
        data.put("assets",assetResponses);
        data.put("totalPage",assets.getTotalPages());
        return new ResponseEntity<>(new Response("Danh sách tài sản",data),HttpStatus.OK);
    }
    //Lấy danh sách Tài sản theo trạng thái tài sản
    @GetMapping("/status/{status}")
    public ResponseEntity<Response> getAssetByStatus(@PathVariable Long status,
                                           @RequestParam(defaultValue = "0") int page,
                                           @RequestParam(defaultValue = "10") int size,
                                           @RequestParam(defaultValue = "assetId") String sort){
        Map<String,Object> data = new HashMap<>();
        Page<Asset> assets = assetService.findAssetByAssetStatus(status,page,size,sort);
        List<AssetResponse> assetResponses = new ArrayList<>();
        for(Asset asset: assets) assetResponses.add(assetMapping.getAssetResponse(asset));
        data.put("assets",assetResponses);
        data.put("totalPage",assets.getTotalPages());
        return new ResponseEntity(new Response("Danh sách tài sản",data),HttpStatus.OK);
    }
    //Lấy danh sách tài sản theo mã người sử dụng
    @GetMapping("/user/{id}")
    public ResponseEntity<Response> getAssetByUserId(@PathVariable Long id,
                                                     @RequestParam(defaultValue = "0") int page,
                                                     @RequestParam(defaultValue = "10") int size,
                                                     @RequestParam(defaultValue = "assetId") String sort){
        Map<String,Object> data = new HashMap<>();
        Page<Asset> assets = assetService.findAssetByUserId(id,page,size,sort);
        List<AssetResponse> assetResponses = new ArrayList<>();
        for(Asset asset: assets) assetResponses.add(assetMapping.getAssetResponse(asset));
        data.put("assets",assetResponses);
        data.put("totalPage",assets.getTotalPages());
        return new ResponseEntity<>(new Response("Danh sách tài sản",data),HttpStatus.OK);
    }
    // Lấy danh sách Tài sản theo Mã loại tài sản
    @GetMapping("/assetType/{id}")
    public ResponseEntity<Response> getAssetByAssetType(@PathVariable Long id,
                                                        @RequestParam(defaultValue = "0") int page,
                                                        @RequestParam(defaultValue = "10") int size,
                                                        @RequestParam(defaultValue = "assetId") String sort){
        Map<String,Object> data = new HashMap<>();
        Page<Asset> assets = assetService.findAssetByAssetType(id,page,size,sort);
        List<AssetResponse> assetResponses = new ArrayList<>();
        for(Asset asset: assets) assetResponses.add(assetMapping.getAssetResponse(asset));
        data.put("assets",assetResponses);
        data.put("totalPage",assets.getTotalPages());
        return new ResponseEntity<>(new Response("Danh sách tài sản",data),HttpStatus.OK);
    }
    //Lấy thông tin tài sản nằm trong khoảng ngày
    @GetMapping("/date")
    public ResponseEntity<Response> getAssetByDate(@RequestParam(defaultValue = "1900-01-01") String fromDate,
                                                   @RequestParam(defaultValue = "2999-12-31") String toDate,
                                                   @RequestParam(defaultValue = "0") int page,
                                                   @RequestParam(defaultValue = "10") int size,
                                                   @RequestParam(defaultValue = "assetId") String sort) throws ParseException {
        Map<String,Object> data = new HashMap<>();
        Page<Asset> assets = assetService.findAssetByDate(new SimpleDateFormat("yyyy-MM-dd").parse(fromDate),new SimpleDateFormat("yyyy-MM-dd").parse(toDate),page,size,sort);
        List<AssetResponse> assetResponses = new ArrayList<>();
        for(Asset asset: assets) assetResponses.add(assetMapping.getAssetResponse(asset));
        data.put("assets",assetResponses);
        data.put("totalPage",assets.getTotalPages());
        return new ResponseEntity<>(new Response("Danh sách tài sản",data),HttpStatus.OK);
    }
    // Lấy thông tin tài sản thông qua từ khóa
    @PostMapping("/keyword")
    public ResponseEntity<Response> getAssetByDate(@RequestBody String name,
                                                   @RequestParam(defaultValue = "0") int page,
                                                   @RequestParam(defaultValue = "10") int size,
                                                   @RequestParam(defaultValue = "asset_id") String sort){
        Map<String,Object> data = new HashMap<>();
        Page<Asset> assets = assetService.findAssetByName(name,page,size,sort);
        List<AssetResponse> assetResponses = new ArrayList<>();
        for(Asset asset: assets) assetResponses.add(assetMapping.getAssetResponse(asset));
        data.put("assets",assetResponses);
        data.put("totalPage",assets.getTotalPages());
        return new ResponseEntity<>(new Response("Danh sách tài sản",data),HttpStatus.OK);
    }



    //API GET ASSET DATA V1
    //Bộ lọc tài sản
    @GetMapping("/filter")
    public ResponseEntity<Response> filterAssets(@RequestParam(defaultValue = "NAMENULL") String name,
                                                 @RequestParam(defaultValue = "-1") Long dept,
                                                 @RequestParam(defaultValue = "-1") Long user,
                                                 @RequestParam(defaultValue = "-1") Long status,
                                                 @RequestParam(defaultValue = "-1") Long assetType,
                                                 @RequestParam(defaultValue = "1000-01-01") String fromDate,
                                                 @RequestParam(defaultValue = "2999-12-31") String toDate,
                                                 @RequestParam(defaultValue = "0") int page,
                                                 @RequestParam(defaultValue = "10") int size,
                                                 @RequestParam(defaultValue = "asset_id") String sort) throws ParseException {
        Map<String,Object> data = new HashMap<>();
        Page<Asset> assets = assetService.filterAssets(name,dept,user,status,assetType,
                    new SimpleDateFormat("yyyy-MM-dd").parse(fromDate),
                    new SimpleDateFormat("yyyy-MM-dd").parse(toDate),
                    page,size,sort);
        List<AssetResponse> assetResponses = new ArrayList<>();
        for(Asset asset: assets) assetResponses.add(assetMapping.getAssetResponse(asset));
        data.put("assets",assetResponses);
        data.put("totalPage",assets.getTotalPages());
        return new ResponseEntity<>(new Response("Danh sách tài sản",data),HttpStatus.OK);
    }
    //Thực hiện lấy thông tin các nhóm tài sản
    @GetMapping("/group")
    public ResponseEntity getGroupAsset(){
        return new ResponseEntity<>(assetGroupService.getAllGroup(),HttpStatus.OK);
    }
    //Thực hiện tạo thông tin tài sản thông qua file Excel
    @PostMapping("/upload-assets-data")
    public ResponseEntity<?> uploadAssetsData(@RequestParam("file") MultipartFile file){
        assetService.saveAssetsToDatabase(file);
        return ResponseEntity
                .ok(Map.of("message" , "Thêm tài sản thành công"));
    }
    //Tạo thông tin tài sản thông qua Records
    @PostMapping("/create")
    public ResponseEntity<Response> createAsset(@RequestBody AssetRequest assetRequest){
        if(assetService.createAsset(assetMapping.getAsset(assetRequest)))
            return new ResponseEntity(new Response("Tạo tài sản thành công",null),HttpStatus.CREATED);
        return new ResponseEntity(new Response("Tạo tài sản thất bại",null),HttpStatus.NOT_ACCEPTABLE);
    }
    //Bàn giao tài sản
    @PutMapping("/user/{id}")
    public ResponseEntity<Response> addUserUsed(@PathVariable Long id, @RequestBody DeliveryRequest deliveryRequest){
        Asset asset = assetService.findAssetById(id);
        if(asset == null) return new ResponseEntity<>(new Response("Không tìm thấy tài sản",null),HttpStatus.NOT_FOUND);
        if(asset.getUserUsedId() != null) return new ResponseEntity<>(new Response("Tài sản đang được sử dụng",null),HttpStatus.NOT_FOUND);
        asset = assetMapping.deliveryAsset(asset,deliveryRequest);
        if(asset == null) return new ResponseEntity<>(new Response("Bàn giao tài sản thất bại",null),HttpStatus.NOT_FOUND);
        assetService.addUserAsset(asset);
        return new ResponseEntity<>(new Response("Cập nhật thông tin thành công",null),HttpStatus.OK);
    }
    //Thu hồi tài sản
    @PutMapping("/recall/{id}")
    public ResponseEntity<Response> recallAsset(@PathVariable Long id,@RequestParam(required = false) String note){
        Asset asset = assetService.findAssetById(id);
        if(asset == null) return new ResponseEntity<>(new Response("Không tìm thấy tài sản",null),HttpStatus.NOT_FOUND);
        if(asset.getUserUsedId() == null) return new ResponseEntity<>(new Response("Tài sản chưa được đưa vào sử dụng",null),HttpStatus.NOT_FOUND);
        asset = assetMapping.recallAsset(asset,note);
        if(asset == null) return new ResponseEntity<>(new Response("Thu hồi tài sản thất bại",null),HttpStatus.NOT_FOUND);
        assetService.recallAsset(asset);
        return new ResponseEntity<>(new Response("Cập nhật thông tin thành công",null),HttpStatus.OK);
    }
    //Thực hiện nâng cấp tài sản
    @PutMapping("/update/{id}")
    public ResponseEntity updateAsset(@PathVariable Long id,@RequestBody UpdateHistoryRequest updateHistoryRequest) throws ParseException {
        Asset asset = assetService.findAssetById(id);
        if(asset == null)
            return new ResponseEntity("Tài sản không tồn tại",HttpStatus.NOT_FOUND);
        if(asset.getUserUsedId() != null|| asset.getDeptUsedId() != null)
            return new ResponseEntity("Tài sản vẫn còn đang sử dụng", HttpStatus.NOT_ACCEPTABLE);
        asset = assetMapping.updateAsset(asset,updateHistoryRequest);
        if(assetService.createAsset(asset)){
            return new ResponseEntity("Nâng cấp tài sản thành công",HttpStatus.OK);
        }
        return new ResponseEntity("Nâng cấp tài sản thất bại",HttpStatus.OK);
    }
    // Đếm số lượng tài sản có trong hệ thống
    @GetMapping("/count")
    public ResponseEntity getCountAsset(){
        return new ResponseEntity(assetService.countAsset(),HttpStatus.OK);
    }
    //Lấy danh sách bàn giao tài sản
    @GetMapping("/delivery/{id}")
    public ResponseEntity getAssetDelivery(@PathVariable Long id){
        Asset asset = assetService.findAssetById(id);
        if(asset.getDateUsed() == null)
            return new ResponseEntity(HttpStatus.NOT_FOUND);
        return new ResponseEntity(assetMapping.getAssetDeliveryResponse(asset),HttpStatus.OK);
    }
    //Lấy danh sách nâng cấp tài sản
    @GetMapping("/update/{id}")
    public ResponseEntity getAllUpdateHistory(@PathVariable Long id) throws ParseException {
        Asset asset = assetService.findAssetById(id);
        List<UpdateHistory> histories = updateHistoryService.getListUpdateHistoryByAssetId(id);
        if(histories.size()== 0)
            return new ResponseEntity(HttpStatus.NOT_FOUND);
        return new ResponseEntity(assetMapping.getAssetUpdateHistoryResponse(asset,histories),HttpStatus.OK);
    }
    //Lấy danh sách giảm tài sản
    @GetMapping("/reduce/{id}")
    public ResponseEntity getAllReduceHistory(@PathVariable Long id) throws ParseException {
        Asset asset = assetService.findAssetById(id);
        List<UpdateHistory> histories = updateHistoryService.getListReduceHistoryByAssetId(id);
        return new ResponseEntity(assetMapping.getAssetUpdateHistoryResponse(asset,histories),HttpStatus.OK);
    }
}
