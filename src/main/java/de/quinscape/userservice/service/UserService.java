package de.quinscape.userservice.service;

import de.quinscape.userservice.model.Role;
import de.quinscape.userservice.model.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    User getUser(String username);
    List<User> getUsers();
}
