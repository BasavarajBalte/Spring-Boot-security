package com.pluralsight.security.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;

//@Configuration
//@Order(1)
public class AdminSecurityCinfiguration extends WebSecurityConfigurerAdapter {

	//when request for authontication diagest will check nonce and response in header having encripted credintials
	// when user authonticated diagest set still isauthonticated = false in Authontication
	// after this Authontication manager will call for this authontication
	//but while authonticating iusing authontication manager credintial will send in plain ttext which
	//will be dengerious security cause.
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.antMatcher("/support/admin/**").addFilter(getDigestAuthFilter()).exceptionHandling()
				.authenticationEntryPoint(getDigestEntryPoint()).and().authorizeRequests()
				.antMatchers("/support/admin/**").hasRole("ADMIN");
	}

	private DigestAuthenticationFilter getDigestAuthFilter() throws Exception {
		DigestAuthenticationFilter filter = new DigestAuthenticationFilter();
		filter.setUserDetailsService(userDetailsServiceBean());
		filter.setAuthenticationEntryPoint((DigestAuthenticationEntryPoint) getDigestEntryPoint());
		return filter;

	}

	private AuthenticationEntryPoint getDigestEntryPoint() {
		DigestAuthenticationEntryPoint entryPoin = new DigestAuthenticationEntryPoint();
		entryPoin.setRealmName("admin-digest-realm");
		entryPoin.setKey("fjkf234234_+");
		return entryPoin;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().withUser("user").password("pass1").roles("USER").and().withUser("admin")
				.password("pass2").roles("ADMIN");
	}

	@Override
	@Bean
	public UserDetailsService userDetailsServiceBean() throws Exception {
		// TODO Auto-generated method stub
		return super.userDetailsServiceBean();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}

}
