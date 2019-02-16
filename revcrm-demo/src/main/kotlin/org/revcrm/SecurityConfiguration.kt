package org.revcrm

import org.revcrm.auth.OpenIDConnectFilter
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.oauth2.client.OAuth2RestTemplate
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter

@Configuration
@EnableWebSecurity
class SecurityConfiguration : WebSecurityConfigurerAdapter() {

    @Autowired
    private val restTemplate: OAuth2RestTemplate? = null

    @Bean
    fun openIdConnectFilter(): OpenIDConnectFilter {
        val filter = OpenIDConnectFilter()
        filter.restTemplate = restTemplate
        return filter
    }

    @Throws(Exception::class)
    override fun configure(http: HttpSecurity) {
        http
            .addFilterAfter(OAuth2ClientContextFilter(),
                AbstractPreAuthenticatedProcessingFilter::class.java)
            .addFilterAfter(OpenIDConnectFilter(),
                OAuth2ClientContextFilter::class.java)
            .httpBasic()
            .authenticationEntryPoint(LoginUrlAuthenticationEntryPoint("/google-login"))
            .and()
            .authorizeRequests()
            .anyRequest().authenticated()
    }

//    override fun configure(http: HttpSecurity) {
//        http
//            .csrf().disable()
//            // make sure we use stateless session; session won't be used to store user's state.
//            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//            .and()
//            // handle an authorized attempts
//            .exceptionHandling().authenticationEntryPoint { req, rsp, e -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED) }
//            .and()
//            // Add a filter to validate the tokens with every request
//            .addFilterAfter(JwtTokenAuthenticationFilter(jwtConfig), UsernamePasswordAuthenticationFilter::class.java)
//            // authorization requests config
//            .authorizeRequests()
//            // allow all who are accessing "auth" service
//            .antMatchers(HttpMethod.POST, jwtConfig.getUri()).permitAll()
//            // must be an admin if trying to access admin area (authentication is also required here)
//            .antMatchers("/gallery" + "/admin/**").hasRole("ADMIN")
//            // Any other request must be authenticated
//            .anyRequest().authenticated()
//    }
//
//    @Bean
//    public override fun userDetailsService(): UserDetailsService {
//        val user = User.withDefaultPasswordEncoder()
//            .username("user")
//            .password("password")
//            .roles("USER")
//            .build()
//
//        return InMemoryUserDetailsManager(user)
//    }
}