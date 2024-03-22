package com.example.service.impl;

import com.example.model.Department;
import com.example.repository.DepartmentRepository;
import com.example.service.DepartmentService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
public class DepartmentServiceImpl implements DepartmentService{
    private final DepartmentRepository departmentRepository;
    @Override
    public List<Department> findAllDepartment() {
        return departmentRepository.findAll();
    }

    @Override
    public Department findDepartmentById(Long id) {
        Optional<Department> department = departmentRepository.findById(id);
        if(department.isPresent())
            return department.get();
        return null;
    }
}
