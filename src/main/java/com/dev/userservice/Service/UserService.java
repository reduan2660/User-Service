package com.dev.userservice.Service;

import com.dev.userservice.domain.AppUser;
import com.dev.userservice.domain.Role;

import java.util.List;

public interface UserService {
    AppUser saveUser(AppUser user);
    Role saveRole(Role role);
    void addRoleToUser(String email, String roleName);
    AppUser getUser(String email);
    List<AppUser> getUsers(); // add pagination
}
