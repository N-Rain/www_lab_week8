package vn.edu.iuh.fit.lab_week_8.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity //cap quyen cho viec sercurity tren tung method
public class SercurityConfig {
    @Autowired
    public void globalConfig(AuthenticationManagerBuilder auth, PasswordEncoder encoder) throws Exception{
        auth.inMemoryAuthentication()
                .withUser(User.withUsername("admin")
                        .password(encoder.encode("admin"))
                        .roles("ADMINS")
                        .build())
                .withUser(User.withUsername("abc")
                        .password(encoder.encode("abc"))
                        .roles("ABC")
                        .build())
                .withUser(User.withUsername("ngoc")
                        .password(encoder.encode("ngoc"))
                        .roles("NGOC")
                        .build());
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity)throws Exception{
        //nhung link nay khong can authenticate
        httpSecurity.authorizeHttpRequests(auth->auth.requestMatchers("/","/home","/index").permitAll()
                //nhung uri bat dau bang /api can phai dang nhap voi cac role admin/user/ngoc
                .requestMatchers("api/**").hasAnyRole("ADMIN","USER","NGOC")
                //uri bat dau bang /admin thi phai dang nhap voi quyen admin
                .requestMatchers(("/admin/**")).hasRole("ADMIN")
                //cac uri khac can dang nhap duoi bat ky voi role nao
                .anyRequest().authenticated());
        //cac thiet lap con lai thi theo mac dinh
        httpSecurity.httpBasic(Customizer.withDefaults());

        return httpSecurity.build();
    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}
