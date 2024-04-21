package com.example.demo.Service;

import com.example.demo.Entity.User;
import com.example.demo.Repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;



import jakarta.servlet.http.HttpSession;

@Service
public class UserServiceImp implements UserService{
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;
    public User AddUser(User user) {
        String password=passwordEncoder.encode(user.getPassword());
        user.setPassword(password);
        user.setRole("ROLE_USER");
        return userRepository.save(user);

    }
    @Override
    public boolean checkEmail(String email) {
        // TODO Auto-generated method stub
        return userRepository.existsByEmail(email);
    }

    @Override
    public void removeSessionMessage() {
        // TODO Auto-generated method stub
        HttpSession session=((ServletRequestAttributes)(RequestContextHolder.getRequestAttributes())).getRequest().getSession();
        session.removeAttribute("msg");
    }

    @Override
    public boolean IsValidName(String str) {
        //String str=user.getFullName();
        if (str.length()<2) {
            return false;
        }

        if (!str.matches("[a-zA-Z]+")) {
            return false;
        }
        return true;
    }
    @Override
    public boolean IsValidEmail(String str) {
        // TODO Auto-generated method stub
        //String str=user.getEmail();
        if(str.length()==0)
            return false;
        if(!str.matches("[a-zA-Z]+[0-9]*@gmail.com"))
            return false;

        return true;
    }
    @Override
    public boolean IsValidPassword(String str) {
        //String password = user.getPassword();

        if (str.length() < 8||str.length() > 15) {
            return false;
        }

        if (!str.matches(".*[A-Z].*")) {
            return false;
        }
        if (!str.matches(".*[0-9].*")) {
            return false;
        }
        if (!str.matches(".*[!@#$%^&*()-_=+\\|\\[{\\]};:'\",<.>/?`~].*")) {
            return false;
        }

        return true;
    }


}