package com.example.service.Impl;

import com.example.client.AssetServiceClient;
import com.example.dto.kafka.AssetEvent;
import com.example.dto.response.UserResponse;
import com.example.mapping.ExcelUpload;
import com.example.model.Asset;
import com.example.model.AssetDelivery;
import com.example.repository.AssetDeliveryRepository;
import com.example.repository.AssetRepository;
import com.example.service.AssetDeliveryService;
import com.example.service.AssetService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.text.Normalizer;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

@Service
@Transactional
@RequiredArgsConstructor
public class AssetServiceImpl implements AssetService {
    private final AssetRepository assetRepository;
    private final AssetServiceClient assetServiceClient;
    private final ExcelUpload excelUpload;
    private final AssetDeliveryRepository assetDeliveryRepository;
    @Autowired
    private KafkaTemplate<String,Object> kafkaTemplate;

    public void saveAssetsToDatabase(MultipartFile file){
        if(ExcelUpload.isValidExcelFile(file)){
            try {
                List<Asset> assets = excelUpload.getAssetsDataFromExcel(file.getInputStream());
                this.assetRepository.saveAll(assets);
            } catch (IOException e) {
                throw new IllegalArgumentException("The file is not a valid excel file");
            }
        }
    }

    public Page<Asset> getAssets(int page, int size, String sort){
        Pageable pageable = PageRequest.of(page,size,Sort.by(sort));
        return assetRepository.findAll(pageable);
    }

    @Override
    public Asset findAssetById(Long id) {
        Optional<Asset> asset = assetRepository.findById(id);
        if(asset.isPresent())
            return asset.get();
        return null;
    }

    @Override
    public Page<Asset> findAssetByDeptId(Long deptId, int page,int size,String sort){
        Pageable pageable = PageRequest.of(page,size, Sort.by(sort));
        return assetRepository.findByDeptUsedId(deptId,pageable);
    }

    @Override
    public Page<Asset> findAssetByUserId(Long userId, int page, int size, String sort) {
        Pageable pageable = PageRequest.of(page,size, Sort.by(sort));
        return assetRepository.findByUserUsedId(userId,pageable);
    }

    @Override
    public Page<Asset> findAssetByAssetStatus(Long assetStatus, int page, int size, String sort) {
        Pageable pageable = PageRequest.of(page,size, Sort.by(sort));
       return assetRepository.findByAssetStatus(assetStatus,pageable);
    }

    @Override
    public Page<Asset> findAssetByDate(Date fromDate, Date toDate, int page, int size, String sort) {
        Pageable pageable = PageRequest.of(page,size);
        return assetRepository.findByStoredDate1(fromDate,toDate,pageable);
    }

    @Override
    public Page<Asset> findAssetByName(String name, int page, int size, String sort) {
        Pageable pageable = PageRequest.of(page,size);
        String keyword = "%(";
        name = covertToString(name.toLowerCase());
        String[] parts = name.split(" ");
        keyword+=String.join("|",parts);
        keyword+=")%";
        return assetRepository.findByKeyword(keyword,pageable);
    }

    @Override
    public Page<Asset> filterAssets(String name, Long deptId, Long userId, Long status,Long assetType, Date fromDate, Date toDate, int page, int size, String sort) {
        Pageable pageable = PageRequest.of(page,size,Sort.by(sort));
        String keyword = "%(";
        name = covertToString(name.toLowerCase());
        String[] parts = name.split(" ");
        keyword+=String.join("|",parts);
        keyword+=")%";
        return assetRepository.filterAssets(keyword,deptId,userId, assetType,fromDate,toDate,status,pageable);
    }

    public static String covertToString(String value) {
        try {
            String temp = Normalizer.normalize(value, Normalizer.Form.NFD);
            Pattern pattern = Pattern.compile("\\p{InCombiningDiacriticalMarks}+");
            return pattern.matcher(temp).replaceAll("");
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    @Override
    public boolean createAsset(Asset asset) {
        if(assetRepository.save(asset)!=null)
            return true;
        return false;
    }

    @Override
    public boolean addUserAsset(Asset asset) {
        //Thực hiện raise thông tin tài sản và tiến hành tính khấu hao
        Asset assetTemp = assetRepository.save(asset);
        AssetEvent event = new AssetEvent();
        event.setEventType("AddUser");
        event.getAssetResponse().setAssetId(asset.getAssetId());
        event.getAssetResponse().setUserId(asset.getUserUsedId());
        event.getAssetResponse().setDeptId(asset.getDeptUsedId());
        kafkaTemplate.send("asset-add-user-event-topic", event);
        if(assetTemp != null)
            return true;
        return false;
    }

    @Override
    public boolean recallAsset(Asset asset) {
        //Thực hiện raise thông tin tài sản và tiến hành tính khấu hao
        Asset assetTemp = assetRepository.save(asset);
        AssetEvent event = new AssetEvent();
        event.setEventType("RecallAsset");
        event.getAssetResponse().setAssetId(asset.getAssetId());
        event.getAssetResponse().setUserId(asset.getUserUsedId());
        event.getAssetResponse().setDeptId(asset.getDeptUsedId());
        kafkaTemplate.send("asset-recall-event-topic", event);
        asset.setUserUsedId(null);
        asset.setDeptUsedId(null);
        asset.setAssetStatus(Long.valueOf(0));
        if(assetTemp != null)
            return true;
        return false;
    }

    @Override
    public long countAsset() {
        return assetRepository.count();
    }


    @Override
    public UserResponse getAssets1() {
        return assetServiceClient.fetchUser(Long.valueOf(1));
    }

    @Override
    public Page<Asset> findAssetByAssetType(Long assetTypeId, int page, int size, String sort) {
        Pageable pageable = PageRequest.of(page, size, Sort.by(sort));
        return assetRepository.findByAssetType(assetTypeId,pageable);
    }
    @KafkaListener(topics = "asset-rollback-event-topic",groupId = "asset-event-group")
    public void processRollbackEvents(AssetEvent event) {
        if(event.getEventType().equals("RollbackAddUser")){
            //Rollback AssetDelivery
            AssetDelivery assetDelivery = assetDeliveryRepository.findByAssetIdAndDeliveryType(event.getAssetResponse().getAssetId(),event.getAssetResponse().getUserId(),Long.valueOf(0));
            assetDelivery.setActive(false);
            assetDeliveryRepository.save(assetDelivery);
            Asset asset = findAssetById(event.getAssetResponse().getAssetId());
            asset.setUserUsedId(null);
            asset.setAssetStatus(Long.valueOf(0));
            asset.setDeptUsedId(null);
            createAsset(asset);
        }
        else if(event.getEventType().equals("RollbackRecall")){
            //Rollback AssetDelivery
            AssetDelivery assetDelivery = assetDeliveryRepository.findByAssetIdAndDeliveryType(event.getAssetResponse().getAssetId(),event.getAssetResponse().getUserId(),Long.valueOf(1));
            assetDelivery.setActive(false);
            assetDeliveryRepository.save(assetDelivery);
            Asset asset = findAssetById(event.getAssetResponse().getAssetId());
            asset.setUserUsedId(event.getAssetResponse().getUserId());
            asset.setAssetStatus(Long.valueOf(1));
            asset.setDeptUsedId(event.getAssetResponse().getDeptId());
            createAsset(asset);
        }
    }

}
