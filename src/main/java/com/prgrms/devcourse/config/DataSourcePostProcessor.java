package com.prgrms.devcourse.config;

import javax.sql.DataSource;
import net.sf.log4jdbc.Log4jdbcProxyDataSource;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.stereotype.Component;

@Component
public class DataSourcePostProcessor implements BeanPostProcessor {

    // DataSource Bean 이 초기화된 후 Log4jdbcProxyDataSource 객체로 감싸서 반환
    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        if (bean instanceof DataSource && !(bean instanceof Log4jdbcProxyDataSource)) {
            return new Log4jdbcProxyDataSource((DataSource) bean);
        } else return bean;
    }
}
