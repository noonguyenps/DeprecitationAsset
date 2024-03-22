package com.example.service;

import com.example.model.Storage;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

@Service
@Component
public interface StorageService {
    Storage findById(Long id);
}
