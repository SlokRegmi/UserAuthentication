package authentication.RESTAuthentication;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EnableJpaRepositories("authentication.RESTAuthentication.repository")
@EntityScan("authentication.RESTAuthentication.entities")
public class RestAuthenticationApplication {
	public static void main(String[] args) {
		SpringApplication.run(RestAuthenticationApplication.class, args);
	}
}


