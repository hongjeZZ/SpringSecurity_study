package com.prgrms.devcourse.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    // 보통 정적인 페이지에 사용한다.
    @Override
    public void configure(WebSecurity web) {
        // 지정된 antPath 경로에는 시큐리티 필터 체인을 태우지 않음. (전역 설정)
        // 필터는 다수의 필터로 구성되기 때문에, 불필요한 요청은 ignoring() 메서드를 통해 제외하도록 한다.
        web.ignoring().antMatchers("/assets/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/me").hasAnyRole("USER", "ADMIN")
                .anyRequest().permitAll()
                .and()
            .formLogin()
                .defaultSuccessUrl("/")
                .permitAll()
                .and();
    }
}
