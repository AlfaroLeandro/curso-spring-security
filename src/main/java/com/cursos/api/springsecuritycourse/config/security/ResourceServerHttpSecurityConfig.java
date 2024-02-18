package com.cursos.api.springsecuritycourse.config.security;

import com.cursos.api.springsecuritycourse.config.security.filter.JwtAuthenticationFilter;
import com.cursos.api.springsecuritycourse.persistence.util.RoleEnum;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity //arranca ciertas configuraciones y pone todo por default
@EnableMethodSecurity(prePostEnabled = true) //habilita componentes especiales para este tipo de seguridad
public class ResourceServerHttpSecurityConfig {

    @Autowired //inyectado desde SecurityBeansInjector
    private AuthenticationProvider authenticationProvider;

//    @Autowired
//    private JwtAuthenticationFilter jwtAuthenticationFilter; -> EN DESUSO

    @Autowired
    private AuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    private AccessDeniedHandler accessDeniedHandler;

    @Autowired
    private AuthorizationManager<RequestAuthorizationContext> authorizationManager;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .cors(Customizer.withDefaults()) //inyecta el filtro de CORS, usa el Bean apiConfigurationSource()
                .csrf(csrfConfig -> csrfConfig.disable())
                .sessionManagement(sessConfig -> sessConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .authenticationProvider(authenticationProvider) //sin uso -> se usa oauth2 ->reemlazado por el jwtAuthenticationConverter
//                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class) // sin uso -> se usa oauth2 ya que se usa jwe y no jwt
                    //me aseguro que se ejecute antes de la autenticacion por usuario y contraseña
//                .authorizeHttpRequests(authReqConfig -> buildRequestMatchers(authReqConfig))
                .authorizeHttpRequests(authReqConfig -> authReqConfig.anyRequest().access(authorizationManager))
                .exceptionHandling(exceptionConfig -> {
                    exceptionConfig.authenticationEntryPoint(authenticationEntryPoint);
                    exceptionConfig.accessDeniedHandler(accessDeniedHandler);
                })
                .oauth2ResourceServer(oauth2rsConfig -> {
                    oauth2rsConfig.jwt(jwtConfig -> jwtConfig.decoder( //le pide al auth server de que forma se debe decodificar el jwt
                                        JwtDecoders.fromOidcIssuerLocation(issuerUri)));
                })
                .build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("permissions"); //tiene que ser el mismo del auth server
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix(""); //no puse ningun prefijo tipo "AUTHORITY_"

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);

        return jwtAuthenticationConverter;
    }

//    @Bean
//    CorsConfigurationSource apiConfigurationSource() {
//        CorsConfiguration configuration = new CorsConfiguration();
//        configuration.setAllowedOrigins(Arrays.asList("http://127.0.0.1:5500"));
//        configuration.setAllowedMethods(Arrays.asList("*"));
//        configuration.setAllowedHeaders(Arrays.asList("*"));
//        configuration.setAllowCredentials(true);
//
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", configuration);
//        return source;
//    }

   @Deprecated
    private void buildRequestMatchers(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authReqConfig) {
    /*
    Autorizacion de endpoints de products
     */
        putAuthoritiesProducts(authReqConfig);

                    /*
                    Autorizacion de endpoints de categories
                     */
//        putAuthoritiesCategories(authReqConfig);

                    /*
                       Autorizacion perfil
                     */
//        authReqConfig.requestMatchers(HttpMethod.GET, "/auth/profile")
//                .hasAnyRole(Role.ADMINISTRATOR.name(),
//                        Role.ASSISTANT_ADMINISTRATOR.name(),
//                        Role.CUSTOMER.name());

                    /*
                     Autorización de endpoints publicos
                     */
        authReqConfig.requestMatchers(HttpMethod.POST,"/customers").permitAll();
        authReqConfig.requestMatchers(HttpMethod.POST,"/auth/authenticate").permitAll(); //permite todos
        authReqConfig.requestMatchers(HttpMethod.GET,"/auth/validate").permitAll(); //permite todos
        authReqConfig.anyRequest().authenticated(); //cualquier otra url, requiere autenticacion
    }

    @Deprecated
    public void putAuthoritiesProducts(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authReqConfig) {
        authReqConfig.requestMatchers(HttpMethod.GET, "/products")
                .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());
        authReqConfig.requestMatchers(HttpMethod.GET, "/products/{productId}")
                .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());
        authReqConfig.requestMatchers(HttpMethod.POST, "/products")
                .hasRole(RoleEnum.ADMINISTRATOR.name());
        authReqConfig.requestMatchers(HttpMethod.PUT, "/products/{productId}")
                .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());
        authReqConfig.requestMatchers(HttpMethod.PUT, "/products/{productId}/disabled")
                .hasRole(RoleEnum.ADMINISTRATOR.name());

    }

    public void putAuthoritiesCategories(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authReqConfig) {
        authReqConfig.requestMatchers(HttpMethod.GET, "/categories")
                .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());
        authReqConfig.requestMatchers(HttpMethod.GET, "/categories/{productId}")
                .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());
        authReqConfig.requestMatchers(HttpMethod.POST, "/categories")
                .hasRole(RoleEnum.ADMINISTRATOR.name());
        authReqConfig.requestMatchers(HttpMethod.PUT, "/categories/{productId}")
                .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());
        authReqConfig.requestMatchers(HttpMethod.PUT, "/categories/{productId}/disabled")
                .hasRole(RoleEnum.ADMINISTRATOR.name());

    }

}
