package com.cursos.api.springsecuritycourse.config.security.authorization;

import com.cursos.api.springsecuritycourse.exception.ObjectNotFoundException;
import com.cursos.api.springsecuritycourse.persistence.entity.security.Operation;
import com.cursos.api.springsecuritycourse.persistence.entity.security.User;
import com.cursos.api.springsecuritycourse.persistence.repository.security.OperationRepository;
import com.cursos.api.springsecuritycourse.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


@Component
public class CustomAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    @Autowired
    private OperationRepository operationRepository;

    @Autowired
    private UserService userService;

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext requestContext) {
        HttpServletRequest request = requestContext.getRequest();
        System.out.println(request.getRequestURL());
        System.out.println(request.getRequestURI());

        String url = extractUrl(request);
        String httpMethod = request.getMethod();

        boolean isPublic = isPublic(url, httpMethod);
        if(isPublic)
            return new AuthorizationDecision(true);

        boolean isGranted = isGranted(url, httpMethod, authentication.get());
        return new AuthorizationDecision(isGranted);
    }

    private boolean isGranted(String url, String httpMethod, Authentication authentication) {
//        if(authentication == null || !(authentication instanceof UsernamePasswordAuthenticationToken))
//            throw new AuthenticationCredentialsNotFoundException("User not logged in");
        if(authentication == null || !(authentication instanceof JwtAuthenticationToken))
            throw new AuthenticationCredentialsNotFoundException("User not logged in");

        JwtAuthenticationToken authToken = (JwtAuthenticationToken) authentication;
        List<Operation> operations = obtainedOperations(authentication);

        boolean isGranted  = operations.stream().anyMatch(op -> {
            return getOperationPredicate(url, httpMethod, op);
        });

        System.out.println("IS GRANTED: " + isGranted);

        return isGranted;
    }

    private List<Operation> obtainedOperations(Authentication authentication) {
        JwtAuthenticationToken authToken = (JwtAuthenticationToken) authentication;
        // String username = (String) authToken.getPrincipal(); // -> username como principal (SIN oauth2)
        Jwt jwt = authToken.getToken(); // jwt como principal
        String username = jwt.getSubject();
        User user = userService.findOneByUsername(username).orElseThrow(() -> new ObjectNotFoundException("User not found. Username: " + username));
        List<Operation> operations =  user.getRole().getPermissions().stream()
                                        .map(grantedPermission -> grantedPermission.getOperation())
                                        .collect(Collectors.toList());

        List<String> scopes = extractScopes(jwt);
        if(!scopes.contains("ALL")) {
            operations = operations.stream()
                            .filter(op -> scopes.contains(op.getName()))
                            .collect(Collectors.toList());
        }

        return operations;
    }

    private List<String> extractScopes(Jwt jwt) {
        List<String> scopes = new ArrayList<>();
        try {
            scopes =  (List<String>) jwt.getClaims().get("scope");
        } catch (Exception e) { //VER LOG4J
            System.out.println("Hubo un problema al extraer los scopes del cliente");
        }

        return scopes;
    }

    private boolean isPublic(String url, String httpMethod) {
        List<Operation> publicAccessEndpoint = operationRepository.findByPublicAccess();

        boolean isPublic = publicAccessEndpoint.stream().anyMatch(op -> {
            return getOperationPredicate(url, httpMethod, op);
        });
        System.out.println("IS PUBLIC: " + isPublic);
        return isPublic;
    }

    private static boolean getOperationPredicate(String url, String httpMethod, Operation op) {
        String basePath = op.getModule().getBasePath();
        Pattern pattern = Pattern.compile(basePath.concat(op.getPath()));
        Matcher matcher = pattern.matcher(url);
        return matcher.matches() && op.getHttpMethod().equals(httpMethod);
    }

    private String extractUrl(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        String url = request.getRequestURI();
        url = url.replace(contextPath, "");
        System.out.println(url);
        return url;
    }
}
