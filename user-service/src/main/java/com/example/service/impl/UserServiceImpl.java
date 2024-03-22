package com.example.service.impl;

import com.example.model.User;
import com.example.repository.UserRepository;
import com.example.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    @Override
    public List<User> findAllUser(Pageable pageable) {
        Page<User> users = userRepository.findAll(pageable);
        return users.toList();
    }

    @Override
    public User findUserById(Long id) {
        Optional<User> user = userRepository.findById(id);
        if(user.isPresent())
            return user.get();
        return null;
    }

    @Override
    public long countUser() {
        return userRepository.count();
    }

    @Override
    public List<User> findUserByDept(Long deptId) {
        return userRepository.findByDept(deptId);
    }
}
