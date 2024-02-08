package com.cursos.api.springsecuritycourse.config.security.filter;

import com.cursos.api.springsecuritycourse.exception.ObjectNotFoundException;
import com.cursos.api.springsecuritycourse.persistence.entity.security.JwtToken;
import com.cursos.api.springsecuritycourse.persistence.repository.security.JwtTokenRepository;
import com.cursos.api.springsecuritycourse.service.UserService;
import com.cursos.api.springsecuritycourse.service.auth.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.swing.text.html.Option;
import java.io.IOException;
import java.util.Date;
import java.util.Optional;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserService userService;

    @Autowired
    private JwtTokenRepository jwtTokenRepository;

    /**
     * Tengo el filter chain de jakarta
     * @param request
     * @param response
     * @param filterChain
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //1.obtener encabezado http llamado authorization
        //2. Obtener JWT desde el encabezado
        String jwt = jwtService.extractJwtFromRequest(request);
        if(jwt==null || !StringUtils.hasText(jwt)) {
            filterChain.doFilter(request, response);
            return;
        }

        //2.1 Obtener token no expirado y valido desde base de datos
        Optional<JwtToken> token = jwtTokenRepository.findByToken(jwt);
        boolean isValid = validateToken(token);

        if(!isValid) {
            filterChain.doFilter(request, response);
            return;
        }

        //3. Obtener el subject/username desde el token
        //esta acción valida formato de token, firma y expiración
        String username = jwtService.extractUsername(jwt);

        //4. Setear objeto authentication dentro del security context holder
        UserDetails userDetails = userService.findOneByUsername(username).orElseThrow(() -> {
            return new ObjectNotFoundException("User not found. Username: " + username);
        });

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                username,
                null,
                userDetails.getAuthorities()
        );

        //WebAuthenticationDetails -> clase envoltoria de HttpServletRequest
        authToken.setDetails(new WebAuthenticationDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);

        //5. ejecutar el resto de filtros
        filterChain.doFilter(request, response);
    } //implementa GenericFilterBean

    private boolean validateToken(Optional<JwtToken> optToken) {
        if(optToken.isPresent() == false) {
            System.out.println("token no existe o no generado en el sistema");
           return false;
        }

        var token = optToken.get();
        Date now = new Date(System.currentTimeMillis());
        boolean isValid = token.isValid() && token.getExpiration().after(now);
        if(!isValid) {
            System.out.println("Token invalido");
            updateTokenStatus(token);
        }

        return isValid;
    }

    private void updateTokenStatus(JwtToken token) {
        token.setValid(false);
        jwtTokenRepository.save(token);
    }
}
