package de.quinscape.userservice;

import de.quinscape.userservice.model.Role;
import de.quinscape.userservice.model.User;
import de.quinscape.userservice.service.UserService;
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
	public PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	/**
	 * initiates and sets up database using hibernate
	 * @param userService
	 * @return
	 */
	@Bean
	public CommandLineRunner run(UserService userService) {
		return args -> {

			// 1. create Roles
			userService.saveRole(new Role(null, "ROLE_USER"));
			userService.saveRole(new Role(null, "ROLE_MANAGER"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));
			userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

			// 2. create users
			userService.saveUser(new User(null, "John Travolta", "john", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "Will Smith", "will", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "Chris Tucker", "chris", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "Jackie Chan", "jackie", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "Curtis Jackson", "curtis", "1234", new ArrayList<>()));

			// 3. assign users
			userService.addRoleToUser("john", "ROLE_ADMIN");
			userService.addRoleToUser("will", "ROLE_USER");
			userService.addRoleToUser("jackie", "ROLE_ADMIN");
			userService.addRoleToUser("chris", "ROLE_SUPER_ADMIN");
			userService.addRoleToUser("curtis", "ROLE_USER");
		};
	}
}


// TODO: Änderung vorgenommen das will ein user ist und kein admin, und im securityconfig eingestellt das users kein zugriff auf /api/users haben, haben die aber trozdem immernoch
// TODO: WHY?
// TODO: Was sind Beans?


// TODO: Logout funktion für postman  (DELETE Request) DeleteMapping in UserResource controller

// AZUBI CAMP KEVIN HATER FRAGE:
// wie stelle ich fest ob an meinem Token gefutscht worden ist


// erstellen von Cookies und das übersenden bei jedem Request nochmal vorstellen (Kevin) als Bild beispiel
// habe dazu kein Front end.



// refresh token vom login ins /api/token/refresh übergeben, über breakpoints gucken wo der fehler mit dem "null" array ist