package com.example.service;

import com.example.model.Brand;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

@Service
@Component
public interface BrandService {
    Brand findById(Long id);
}
