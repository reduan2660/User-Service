package com.dev.userservice;

import com.dev.userservice.Service.UserService;
import com.dev.userservice.domain.AppUser;
import com.dev.userservice.domain.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class UserserviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserserviceApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService){
		return args -> {
			userService.saveRole(new Role(null, "ROLE_ADMIN"));
			userService.saveRole(new Role(null, "ROLE_ORGANIZATION_ADMIN"));
			userService.saveRole(new Role(null, "ROLE_USER"));

			userService.saveUser(new AppUser(null, "Admin", "admin@email.com", "1234", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "OrganizationAdmin", "org@email.com", "1234", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Test User", "user1@email.com", "1234", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Test User 2", "user2@email.com", "1234", new ArrayList<>()));

			userService.addRoleToUser("admin@email.com", "ROLE_ADMIN");
			userService.addRoleToUser("org@email.com", "ROLE_ORGANIZATION_ADMIN");
			userService.addRoleToUser("user1@email.com", "ROLE_USER");
			userService.addRoleToUser("user2@email.com", "ROLE_USER");
		};
	}

}
