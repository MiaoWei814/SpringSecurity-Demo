package com.miao.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @program: SpringSecurityDemo
 * @description:
 * @author: MiaoWei
 * @create: 2021-10-01 20:31
 **/
//理解AOP的好处,横切进去,不改变原有代码就能实现
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //可以链式编程
    //授权
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //首页所有人都可以访问,但功能页只能有对应权限的人才能访问
        //增加认证请求
        http.authorizeRequests()
                //添加一个地址,所有人都可以访问
                .antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");

        //没有权限默认会跳转到登录页面
        http.formLogin()
                .loginPage("/toLogin")
                .loginProcessingUrl("/login")// 登陆表单提交请求
                .usernameParameter("name")
                .passwordParameter("pwd");

        //注销,开启了注销功能,注销成功跳转到首页
        http.logout().logoutSuccessUrl("/");

        //关闭csrf功能:跨站请求伪造,默认只能通过post方式提交logout请求
        http.csrf().disable();

        //记住我,默认存储为14天
        http.rememberMe().rememberMeParameter("remember");
    }

    @Override
    //认证
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //可以从内存拿可以从jdbc中去拿
        //auth.jdbcAuthentication() jdbc中拿
//        auth.inMemoryAuthentication() 内存中拿
        //从内存中获取-从哪个用户-密码-获取权限(本身是数组,可设置多个)
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder()) //这个也是较为推荐的
                .withUser("miao").password(new BCryptPasswordEncoder().encode("123456")).roles("vip2", "vip3")
                //多个用户以and中间拼接
                .and()
                .withUser("root").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1", "vip2", "vip3")
                .and()
                .withUser("guest").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1");
    }
}
