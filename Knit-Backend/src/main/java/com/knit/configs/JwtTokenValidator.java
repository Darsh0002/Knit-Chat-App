package com.knit.configs;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenValidator extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;

    private final CustomUserDetailsService customUserDetailsService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String header = request.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String token = header.substring(7);
            String email = jwtProvider.getEmailFromToken(token);

            UserDetails userDetails =
                    customUserDetailsService.loadUserByUsername(email);

            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

            SecurityContextHolder.getContext().setAuthentication(auth);

        } catch (ExpiredJwtException e) {
            log.warn("JWT token is expired: {}", e.getMessage());
            response.sendError(
                    HttpServletResponse.SC_UNAUTHORIZED,
                    "Token has expired"
            );
            return;

        } catch (JwtException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            response.sendError(
                    HttpServletResponse.SC_UNAUTHORIZED,
                    "Invalid JWT token"
            );
            return;

        } catch (Exception e) {
            log.error("Authentication failed: {}", e.getMessage());
            response.sendError(
                    HttpServletResponse.SC_UNAUTHORIZED,
                    "Authentication failed"
            );
            return;
        }

        filterChain.doFilter(request, response);
    }
}