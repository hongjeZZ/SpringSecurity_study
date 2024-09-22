package com.prgrms.devcourse.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationEventHandler {

    private final Logger log = LoggerFactory.getLogger(getClass());

    /*
    주의해야 할 부분은 Spring 의 이벤트 모델이 동기적이라는 것이다.
    따라서 이벤트를 구독하는 리스너의 처리 지연은 이벤트를 발생시킨 요청의 응답 지연에 직접적인 영향을 미친다.
    예를 들어 아래 하나의 메서드에 Thread.sleep(m); 를 넣는다면, 클라이언트는 이 지연 시간만큼 대기하게 된다.

    하지만 @Async 어노테이션을 활성화시키면 서로 다른 Thread 에서 동작하므로, 이벤트와 응답 처리는 독립적으로 동작하게 된다.
    +) WebMvcConfigurer 를 상속받는 WebMvcConfig 클래스에도 @EnableAsync 어노테이션을 붙여주어야 한다.
    */

    @Async
    @EventListener
    public void handleAuthenticationSuccessEvent(AuthenticationSuccessEvent event) {
        Authentication authentication = event.getAuthentication();
        log.info("Successful authentication result -> {}", authentication.getPrincipal());
    }

    @EventListener
    public void handleAuthenticationFailureEvent(AbstractAuthenticationFailureEvent event) {
        Exception exception = event.getException();
        Authentication authentication = event.getAuthentication();
        log.info("Failure authentication result -> {}", authentication.getPrincipal(), exception);
    }

    @EventListener
    public void handleBadCredentialsEvent(AuthenticationFailureBadCredentialsEvent event) {
        Exception exception = event.getException();
        Authentication authentication = event.getAuthentication();
        log.info("BadCredentials result -> {}", authentication.getPrincipal(), exception);
    }
}
