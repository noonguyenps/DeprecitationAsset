package com.example.security.service;

import com.example.model.User;
import com.example.repository.UserRepository;
import com.example.security.DTO.AppUserDetail;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AppUserDetailService implements UserDetailsService {
    private static final Logger LOGGER = LogManager.getLogger(AppUserDetailService.class);
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String id) throws UsernameNotFoundException {
        Optional<User> userEntity = userRepository.findById(Long.valueOf(id));
        if(userEntity.isEmpty())
        {
            throw new UsernameNotFoundException("User not found");
        }
        LOGGER.info(userEntity.get().getFullName());
        return AppUserDetail.build(userEntity.get());
    }
}
