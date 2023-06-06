package com.kodlamaio.commonpackage.utils.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class KeycloakJwtRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    //Security nin beklediği class: GrantedAuthority, buna dönüştürmemiz lazım

    private final static String ROLE_PREFIX = "ROLE_"; // yanlışlık olmasın diye

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        return extractRoles(jwt); //jwt içine alacak- alttaki metodu buraya da yazabilirdik daha temiz dursun diye böyle yazdık

    }

    private Collection<GrantedAuthority> extractRoles(Jwt jwt) { // Jwt si olacak
        var claims = jwt.getClaims(); // öncelikle jwt içinden claimleri almamız lazım
        //claim ler jwt de token ımızı yazdığımızda çıkan payload ın tamamını kapsar
        var realmAccess = (Map<String, Object>) // bize gerekli olan "realm_access" kısmı
                // OrDefault = realm acces i bulmaya çalış, bulamazsan boş bir map döndür
                // var ile obje dönüyor ama biz Map tipinde <String, Obje> dönmesi lazımdı
                claims.getOrDefault("realm_access", Collections.emptyMap());
        //roles in içindeki stringlere ulaştık roles in içinde bir şey yoksa boş bir liste dön
        var roles = (List<String>) realmAccess.getOrDefault("roles", Collections.emptyList());
        return roles.stream()
                // her bir rol için SimpleGrantedAuthority oluştrucak
                //SimpleGrantedAuthority bunu oluştururken önüne ROLE_PREFIX eklicek
                .map(role -> new SimpleGrantedAuthority(ROLE_PREFIX + role))
                // sonra bunu bir collection a çevirdim : Collection of GrantedAuthority (Collection<GrantedAuthority>)
                .collect(Collectors.toList());

    }
}
//SimpleGrantedAuthority :Granted Authority ı kullanan bir class