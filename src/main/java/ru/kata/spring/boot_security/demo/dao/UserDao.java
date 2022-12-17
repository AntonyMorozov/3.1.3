package ru.kata.spring.boot_security.demo.dao;

import ru.kata.spring.boot_security.demo.model.User;

import java.util.List;

public interface UserDao {
    List<User> getAllUsers();

    void saveUser(User user);

    User getUserById(int id);

    void updateUser(User user);

    void deleteUserById(int id);

    List<User> findByUsername(String username);
}
