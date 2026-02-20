package jkt.gs.config.filter;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_ORIGINAL_REQUEST_URL_ATTR;

@Component
public class ForwardAuthGatewayFilterFactory
    extends AbstractGatewayFilterFactory<ForwardAuthGatewayFilterFactory.Config> {

    private static final String AUTH_USER_ID = "X-Auth-User-Id";
    private static final String AUTH_PROVIDER = "X-Auth-Provider";
    private static final String AUTH_ROLE = "X-Auth-Role";
    private static final String AUTH_SESSION = "X-Auth-Session";
    private static final String GATEWAY_SECRET_HEADER = "X-Gateway-Secret";
    private static final String PROVIDER_OE = "oe";

    private final WebClient webClient;

    @Value("${gateway.secret.key}")
    private String gsKey;

    public ForwardAuthGatewayFilterFactory(WebClient.Builder builder, @Value("${gateway.uri.oe}") @NonNull String oeUri) {
        super(Config.class);
        this.webClient = builder.baseUrl(oeUri).build();
    }

    public static class Config {}

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();
            boolean isApiPath = isApiPath(path);

            if (path.startsWith("/auth") || path.startsWith("/token")) {
                return chain.filter(exchange);
            }

            String accessToken = cookieValue(request, "accessToken");
            String refreshToken = cookieValue(request, "refreshToken");

            boolean hasAccess = !isBlank(accessToken);
            boolean hasRefresh = !isBlank(refreshToken);

            if (hasAccess) {
                return validateAndForward(exchange, chain, accessToken)
                    .onErrorResume(e -> {
                        if (!hasRefresh) {
                            return authFailure(exchange, request, isApiPath);
                        }
                        return refreshAndForward(exchange, chain, refreshToken)
                            .onErrorResume(err -> authFailure(exchange, request, isApiPath));
                    });
            }

            if (hasRefresh) {
                return refreshAndForward(exchange, chain, refreshToken)
                    .onErrorResume(e -> authFailure(exchange, request, isApiPath));
            }

            if (isApiPath) {
                return unauthorized(exchange);
            }

            return redirectToLogin(exchange, request);
        };
    }

    private Mono<Void> validateAndForward(ServerWebExchange exchange, GatewayFilterChain chain, String accessToken) {
        return webClient.post()
            .uri("/token/validate")
            .headers(h -> {
                h.setBearerAuth(accessToken);
                h.set(HttpHeaders.USER_AGENT, "gs");
                h.set(GATEWAY_SECRET_HEADER, this.gsKey);
            })
            .retrieve()
            .onStatus(status -> !status.is2xxSuccessful(), resp -> Mono.error(new RuntimeException("Invalid token")))
            .toBodilessEntity()
            .flatMap(resp -> forwardWithIdentity(exchange, chain, resp.getHeaders()));
    }

    private Mono<Void> refreshAndForward(ServerWebExchange exchange, GatewayFilterChain chain, String refreshToken) {
        return webClient.post()
            .uri("/token/refresh")
            .headers(h -> {
                h.set("refreshToken", refreshToken);
                h.set(HttpHeaders.USER_AGENT, "gs");
                h.set(GATEWAY_SECRET_HEADER, this.gsKey);
            })
            .retrieve()
            .onStatus(status -> !status.is2xxSuccessful(), resp -> Mono.error(new RuntimeException("Invalid token")))
            .toBodilessEntity()
            .flatMap(resp -> {
                copySetCookies(exchange, resp.getHeaders());
                return forwardWithIdentity(exchange, chain, resp.getHeaders());
            });
    }

    private Mono<Void> forwardWithIdentity(ServerWebExchange exchange, GatewayFilterChain chain, HttpHeaders headers) {
        String userId = headers.getFirst(AUTH_USER_ID);
        String provider = firstNonBlank(headers.getFirst(AUTH_PROVIDER), PROVIDER_OE);
        String role = headers.getFirst(AUTH_ROLE);
        String session = headers.getFirst(AUTH_SESSION);

        if (isBlank(userId) || isBlank(provider)) {
            return unauthorized(exchange);
        }

        ServerWebExchange authExchange = withAuthHeaders(exchange, userId, provider, role, session);
        return chain.filter(authExchange);
    }

    private static ServerWebExchange withAuthHeaders(ServerWebExchange exchange, String userId, String provider, String role, String session) {
        ServerHttpRequest requestWithAuth = exchange.getRequest().mutate()
            .headers(headers -> {
                headers.remove(AUTH_USER_ID);
                headers.remove(AUTH_PROVIDER);
                headers.remove(AUTH_ROLE);
                headers.remove(AUTH_SESSION);

                headers.set(AUTH_USER_ID, userId);
                headers.set(AUTH_PROVIDER, provider);

                if (!isBlank(role)) {
                    headers.set(AUTH_ROLE, role);
                }

                if (!isBlank(session)) {
                    headers.set(AUTH_SESSION, session);
                }
            })
            .build();

        return exchange.mutate().request(requestWithAuth).build();
    }

    private static void copySetCookies(ServerWebExchange exchange, HttpHeaders headers) {
        var setCookies = headers.get(HttpHeaders.SET_COOKIE);
        if (setCookies == null) {
            return;
        }

        setCookies.forEach(cookie -> exchange.getResponse().getHeaders().add(HttpHeaders.SET_COOKIE, cookie));
    }

    private static Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    private static Mono<Void> authFailure(ServerWebExchange exchange, ServerHttpRequest request, boolean isApiPath) {
        if (isApiPath) {
            return unauthorized(exchange);
        }
        return redirectToLogin(exchange, request);
    }

    private static Mono<Void> redirectToLogin(ServerWebExchange exchange, ServerHttpRequest request) {
        URI originalRequestUri = resolveOriginalRequestUri(exchange, request);
        String originalPath = originalRequestUri.getRawPath();
        String originalQuery = originalRequestUri.getRawQuery();
        String redirectTo = "/auth/login";

        if (originalPath != null && !originalPath.isEmpty()) {
            String back = originalPath + (originalQuery != null ? "?" + originalQuery : "");
            try {
                redirectTo = redirectTo + "?redirect=" + URLEncoder.encode(back, StandardCharsets.UTF_8.name());
            } catch (UnsupportedEncodingException e) {
                redirectTo = "/auth/login";
            }
        }

        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.SEE_OTHER);
        response.getHeaders().set("Location", redirectTo);
        return response.setComplete();
    }

    private static URI resolveOriginalRequestUri(ServerWebExchange exchange, ServerHttpRequest fallbackRequest) {
        Set<URI> originalRequestUris = exchange.getAttribute(GATEWAY_ORIGINAL_REQUEST_URL_ATTR);
        if (originalRequestUris != null && !originalRequestUris.isEmpty()) {
            return originalRequestUris.iterator().next();
        }
        return fallbackRequest.getURI();
    }

    private static boolean isApiPath(String path) {
        if (isBlank(path)) {
            return false;
        }

        return path.equals("/ast-api")
            || path.startsWith("/ast-api/")
            || path.equals("/api")
            || path.startsWith("/api/")
            || path.equals("/dashboard/api")
            || path.startsWith("/dashboard/api/");
    }

    private static String cookieValue(ServerHttpRequest request, String name) {
        HttpCookie cookie = request.getCookies().getFirst(name);
        if (cookie == null) {
            return null;
        }
        return cookie.getValue();
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static String firstNonBlank(String value, String fallback) {
        return isBlank(value) ? fallback : value;
    }
}
