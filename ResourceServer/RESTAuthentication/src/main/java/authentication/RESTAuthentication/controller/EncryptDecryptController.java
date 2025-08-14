package authentication.RESTAuthentication.controller;

import authentication.RESTAuthentication.util.EncryptDecrypt;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
@RestController
@RequestMapping("/dataSecurity")
public class EncryptDecryptController {
    @PostMapping("/encryptData")

    public ResponseEntity<String> encryptData(@RequestAttribute("dataToEncrypt") Map<String,Object> dataToEncrypt) throws Exception {
        EncryptDecrypt encryptDecrypt = null;
        System.out.println("Data to encrypt: " + dataToEncrypt);
        try {

            encryptDecrypt.encrypt(dataToEncrypt.toString());
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.badRequest().body("Error during encryption: " + e.getMessage());
        }
        return ResponseEntity.ok("EncryptedData" + encryptDecrypt.encrypt(dataToEncrypt.toString()));
    }
}
