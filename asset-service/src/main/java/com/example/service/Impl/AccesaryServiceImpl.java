package com.example.service.Impl;

import com.example.model.Accessary;
import com.example.repository.AccessaryRepository;
import com.example.service.AccesaryService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
@Service
@Transactional
@RequiredArgsConstructor
public class AccesaryServiceImpl implements AccesaryService {
    @Autowired
    AccessaryRepository accessaryRepository;

    @Override
    public List<Accessary> findByAssetId(Long id) {
        return accessaryRepository.findByAssetId(id);
    }

    @Override
    public Accessary save(Accessary accessary) {
        return accessaryRepository.save(accessary);
    }
}
