package com.wangfugui.apprentice.dao.domain;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

@Data
public class Role {
    private Long id;
    private String roleName;
    private Integer sort;
    private String roleDesc;
}