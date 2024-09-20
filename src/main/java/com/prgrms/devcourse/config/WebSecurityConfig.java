package com.prgrms.devcourse.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    // 로그인 가능한 계정 추가
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user").password("{noop}user123").roles("USER")
                .and()
                .withUser("admin").password("{noop}admin123").roles("ADMIN");
    }

    /*
    보통 정적인 페이지에 사용한다.
    지정된 antPath 경로에는 시큐리티 필터 체인을 태우지 않음. (전역 설정)
    필터는 다수의 필터로 구성되기 때문에 (비효율적인 이유), 불필요한 요청은 ignoring() 메서드를 통해 제외하도록 한다.
    */
    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/assets/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            /*
            spring security 는 /me 경로로 사용자가 들어왔을 때, "me" view 경로로 보내기 전 권한 여부를 파악하고
            스스로 login 페이지로 redirection 처리한다.
            */
            .authorizeRequests()
                .antMatchers("/me").hasAnyRole("USER", "ADMIN")
                .anyRequest().permitAll()
                .and()
            .formLogin()
                .defaultSuccessUrl("/")
                .permitAll()
                .and()
            .rememberMe()
                .tokenValiditySeconds(300);
    }
}
