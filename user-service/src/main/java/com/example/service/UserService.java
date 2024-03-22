package com.example.service;

import com.example.model.User;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.List;

@Component
@Service
public interface UserService {
    List<User> findAllUser(Pageable pageable);
    User findUserById(Long id);
    long countUser();
    List<User> findUserByDept(Long deptId);
}
