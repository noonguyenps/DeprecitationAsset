package com.example.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserResponse {
    private long id;
    private String fullName;
    private String image;
    private Dept dept;
    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public class Dept{
        private int id;
        private String name;
        private String location;
    }
}
