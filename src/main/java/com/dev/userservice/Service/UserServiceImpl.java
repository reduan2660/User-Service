package com.dev.userservice.Service;

import com.dev.userservice.Repo.RoleRepo;
import com.dev.userservice.Repo.UserRepo;
import com.dev.userservice.domain.AppUser;
import com.dev.userservice.domain.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service @RequiredArgsConstructor @Transactional @Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;

    // maps built in user detail service to our custom user model
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        AppUser user = userRepo.findAppUserByEmail(email);
        if(user == null){
            log.error("User not found");
            throw new UsernameNotFoundException("User not found");
        }else{
            log.info("User found {}", email);
        }

        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });

        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), authorities);
    }

    @Override
    public AppUser saveUser(AppUser user) {
//        Validation goes here
        log.info("saving new user {} to the database", user.getName());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("saving new role {} to the database", role.getName());
        return roleRepo.save(role);
    }

    @Override
    public void addRoleToUser(String email, String roleName) {
        log.info("adding role {} to user {}", roleName, email);
        AppUser user = userRepo.findAppUserByEmail(email);
        Role role = roleRepo.findRoleByName(roleName);
        user.getRoles().add(role);
    }

    @Override
    public AppUser getUser(String email) {
        log.info("Getting user by email {} ", email);
        return userRepo.findAppUserByEmail(email);
    }

    @Override
    public List<AppUser> getUsers() {
//        Pagination
        log.info("Fetching all users");
        return userRepo.findAll();
    }
}
