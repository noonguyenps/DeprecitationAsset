package com.example.service.Impl;

import com.example.model.Storage;
import com.example.repository.StorageRepository;
import com.example.service.StorageService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
public class StorageServiceImpl implements StorageService {
    private final StorageRepository storageRepository;
    @Override
    public Storage findById(Long id) {
        Optional<Storage> storage = storageRepository.findById(id);
        if(storage.isPresent())
            return storage.get();
        return null;
    }
}
