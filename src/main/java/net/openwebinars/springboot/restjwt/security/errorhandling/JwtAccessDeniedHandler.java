package net.openwebinars.springboot.restjwt.security.errorhandling;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    //private final ObjectMapper objectMapper;

    private HandlerExceptionResolver resolver;

    @Autowired
    public JwtAccessDeniedHandler(@Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
        this.resolver = resolver;
    }

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {
       /*response.setStatus(HttpStatus.FORBIDDEN.value());
       response.setContentType("application/json");

       response.getWriter()
               .println(objectMapper.writeValueAsString(
                       Map.of("error", accessDeniedException.getMessage())
               ));


        */

        resolver.resolveException(request, response, null, accessDeniedException);

    }
}
