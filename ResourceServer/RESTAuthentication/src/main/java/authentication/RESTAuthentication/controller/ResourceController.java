package authentication.RESTAuthentication.controller;

import authentication.RESTAuthentication.util.EncryptDecrypt;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Map;

@RestController
@RequestMapping("/api/resource")
public class ResourceController {

    @PostMapping("/protected")
    public String getProtectedResource(@AuthenticationPrincipal String username) {
System.out.println("Accessing protected resource with username: " + username);

        return "Hello " + "! This is a protected resource for user ID: " ;
    }

    @PostMapping("/thisIsExample")
    public ResponseEntity<String> encryptData(@RequestAttribute("completeData") Map<String, String> completeData) throws Exception {
       System.out.println("ENTEREDDDD") ;
        for (Map.Entry<String, String> entry : completeData.entrySet()) {
            System.out.println("Key: " + entry.getKey() + ", Value: " + entry.getValue());
        }
    return
        ResponseEntity.ok("Data received successfully: " + completeData.toString());
    }
}