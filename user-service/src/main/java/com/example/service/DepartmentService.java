package com.example.service;

import com.example.model.Department;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.List;

@Component
@Service
public interface DepartmentService {
    public List<Department> findAllDepartment();
    Department findDepartmentById(Long id);
}
