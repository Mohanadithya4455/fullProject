package com.example.demo.Controller;

import javax.validation.Valid;

import com.example.demo.Entity.User;
import com.example.demo.Service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;




import jakarta.servlet.http.HttpSession;


@Controller
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("/profile")
    public String profile() {
        return "profile";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }
    @GetMapping("/register")
    public String register() {
        return "register";
    }
    @PostMapping("/createUser")
    public String AddUser(@ModelAttribute User user, HttpSession session) {

        boolean f=userService.checkEmail(user.getEmail());
        if(f)
        {
            session.setAttribute("msg","Email Id already Exist");
        }
        else if(!userService.IsValidName(user.getFullName())) {
            session.setAttribute("msg", "Please Enter the Valid Name");
        }
        else if(!userService.IsValidEmail(user.getEmail())) {
            session.setAttribute("msg", "Please Enter the Valid Mail");
        }
        else if(!userService.IsValidPassword(user.getPassword())) {
            session.setAttribute("msg", "Password must contain atleast 8 characters,atleast 1 uppercase, 1 special character and 1 digit");
        }
        else {
            User user1=userService.AddUser(user);
            if(user1!=null) {
                session.setAttribute("msg","Registered Successfully");
            }else {
                session.setAttribute("msg","Something went wrong");
            }
        }


        return "redirect:/register";
    }
}