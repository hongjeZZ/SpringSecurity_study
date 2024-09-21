package com.prgrms.devcourse.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    /*
    로그인 가능한 계정 추가
    Spring Security 5에서는 DelegatingPasswordEncoder 가 기본 PasswordEncoder 로 사용된다.
    DelegatingPasswordEncoder 클래스는 패스워드 해시 알고리즘별로 PasswordEncoder 를 제공하는 객체이다 (실제 Encoder 를 감싸는 객체)
    해시 알고리즘별 PasswordEncoder 선택을 위해 패스워드 앞에 prefix 를 추가해줘야 한다. (prefix 생략 시 bcrypt 적용)
    default -> {bcrypt}, passwordEncoder 사용 x -> {noop}, 나머지 -> {pbkdf2}, {sha256} 등등

    +) UserDetailsPasswordService 인터페이스 구현체를 통해 최초 로그인 1회 성공 시,
    {noop} 타입에서 → {bcrypt} 타입으로 PasswordEncoder 가 변경된다.
    +) DelegatingPasswordEncoder 사용이 필요 없다면 BCryptPasswordEncoder 클래스를 명시적으로 Bean 선언하자
    */
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
            spring security 는 "/me" 경로로 사용자가 들어왔을 때, "me" view 경로로 보내기 전 권한 여부를 파악하고
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
            /*
            "/logout" 경로로 접근 시 로그아웃 실행, "/" 로그아웃 성공 시 리다이렉션
            invalidateHttpSession(true) -> 로그아웃 시 해당 사용자의 세션을 invalidate
            clearAuthentication(true) -> 로그아웃된 사용자의 SecurityContext 의 Authentication 을 null 로 초기화
            +) 추가로 아래 설정은 전부 default 값임
            */
            .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .and()
            // 쿠키 기반 자동 로그인 활성화
            .rememberMe()
                .rememberMeParameter("remember-me")
                .tokenValiditySeconds(300)
                .and()
            // 모든 HTTP 요청을 HTTPS 요청으로 리다이렉트
            .requiresChannel()
                .anyRequest().requiresSecure()
                .and()
            // AnonymousAuthenticationFilter 세부 설정
            .anonymous()
                .principal("thisIsAnonymousUser")
                .authorities("ROLE_ANONYMOUS", "ROLE_UNKNOWN")
            ;
    }
}
