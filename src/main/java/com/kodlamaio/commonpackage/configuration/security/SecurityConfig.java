package com.kodlamaio.commonpackage.configuration.security;

import com.kodlamaio.commonpackage.utils.security.KeycloakJwtRoleConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration // konfigürasyon class ı yani altında bean arayacak
@EnableMethodSecurity(securedEnabled = true) // kullanıcılar rollere göre metot bazlı security sağlamış olduk
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        var converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new KeycloakJwtRoleConverter());

        http.cors().and().authorizeHttpRequests()// http isteklerini authorize edicek
                //kayıt olayan kullanılar da erişsin; /api/cars/check-car-available: car clients den geldi
                //yıldızlar da devamında ne gelirse kabul anlamında
                .requestMatchers("/api/filters", "/api/cars/check-car-available/**", "/api/payments/check")
                //hepsine izin ver
                .permitAll()
                .requestMatchers("/api/**")
                // controller getAll da admin verdik o nedenle normal bir user getAll a erişemez ama getById gibi isteklere erişir
                // örneğin getbyid ye de erişmesi için role ihtiyacı var
                .hasAnyRole("user")
                //herhangi bir isteği
                .anyRequest()
                ///api/**" bu url ye uyan gelen tüm istekleri user rolüne göre authenticat et
                .authenticated()
                .and()
                // crass side request for "csrf" :araya saldırı girmeye çalışıyor
                //postman için disable bırakıyoruz, disable nin zararı yok çünkü biz jwt kullanıyoruz buradaki tokenlera
                // bu saldırılar bir şey yapamıyor; api kullanıyorsak disable edebilirz sorun yok
                .csrf().disable()
                // Resource Server ımızı söylüyor
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(converter);

        return http.build(); // bizden converter istiyor: üstte oluşturduk
    }
}
// security configuration hazır