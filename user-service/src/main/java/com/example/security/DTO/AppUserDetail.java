package com.example.security.DTO;

import com.example.common.AppUserRole;
import com.example.model.Role;
import com.example.model.User;
import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

public class AppUserDetail implements UserDetails {
    private static final long serialVersionUID = 1L;
    private String id;
    @JsonIgnore
    private String password;
    @JsonIgnore
    private Collection<? extends GrantedAuthority> authorities;
    private Collection<String> roles;

    public AppUserDetail(String id, String password, Collection<? extends GrantedAuthority> authorities, Collection<String> roles) {
        this.id = id;
        this.password = password;
        this.authorities = authorities;
        this.roles = roles;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public static AppUserDetail build(User user) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        Set<String> roleNames = new HashSet<>();

        for(Role role : user.getRoles()){
            roleNames.add(role.getName());
            for(AppUserRole item : AppUserRole.values()){
                if(role.getName().equals(item.name())){
                    authorities.addAll(item.getGrantedAuthorities());
                }
            }
        }
        return new AppUserDetail(
                user.getId().toString(),
                user.getPassword(),
                authorities,
                roleNames);
    }
    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return id;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
    public Collection<String> getRoles() {
        return roles;
    }
    public String getId() {
        return id;
    }
}
