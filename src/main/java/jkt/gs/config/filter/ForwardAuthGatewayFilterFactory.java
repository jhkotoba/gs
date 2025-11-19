package jkt.gs.config.filter;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;

/**
 * ForwardAuthGatewayFilterFactory는 Spring Cloud Gateway의
 * Custom GatewayFilterFactory로, 요청에 포함된 accessToken 쿠키를
 * 외부 인증 서버(oe)로 전달하여 토큰 유효성을 검증하고,
 * 인증이 실패하면 401 에러를 반환합니다.
 */
@Component
public class ForwardAuthGatewayFilterFactory
    extends AbstractGatewayFilterFactory<ForwardAuthGatewayFilterFactory.Config> {	
	
	// WebClient 인스턴스: 외부 인증 서버 호출에 사용
	private final WebClient webClient;
	
	// Gateway와 OE 서버 간의 비밀 키 (application.yml의 gateway.secret.key)
	@Value("${gateway.secret.key}")
	private String gsKey;
	
    /**
     * 생성자: WebClient.Builder를 주입받아
     * OE 서버의 baseUrl을 설정하여 WebClient를 초기화합니다.
     * 
     * oeUri: OE 서버 기본 URI (application.yml의 gateway.uri.oe)
     *
     * @param builder Spring이 제공하는 WebClient.Builder
     */
	public ForwardAuthGatewayFilterFactory(WebClient.Builder builder, @Value("${gateway.uri.oe}") @NonNull String oeUri) {
		super(Config.class);
		this.webClient = builder.baseUrl(oeUri).build();
	}

    /**
     * 필터 설정용 빈 클래스. 현재 옵션 필드가 없어도 기본 생성자 필요.
     */
    public static class Config {}

    /**
     * GatewayFilter를 생성하는 메서드.
     * Config 객체를 통해 전달된 설정값을 바탕으로 필터 로직을 구현합니다.
     *
     * @param config 필터 설정정보 (현재 미사용)
     * @return GatewayFilter 구현체
     */
    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
        	
        	// 요청객체
        	ServerHttpRequest request = exchange.getRequest();
        	
        	// URI 경로 가져오기
        	String path = request.getURI().getPath();
        	
        	// 인증 자체 경로는 패스(자기호출/루프 방지)
            if (path.startsWith("/auth") || path.startsWith("/token")) {
                return chain.filter(exchange);
            }
            
        	// Cookie 에서 Access 토큰 추출
        	HttpCookie access = request.getCookies().getFirst("accessToken");
        	String accessToken = access == null ? "" : access.getValue();
        	
        	// Cookie 에서 Refresh 토큰 추출
        	HttpCookie refresh = request.getCookies().getFirst("refreshToken");
        	String refreshToken = refresh == null ? "" : refresh.getValue();
            
            // 인증체크
            if(Objects.nonNull(access) && Objects.nonNull(refresh)) {
            	// 인증 체크
                return webClient.post()
                    .uri("/token/validate") // 토큰 검증 엔드포인트
                    .headers(h -> {
                        h.setBearerAuth(accessToken);                       
                        h.set("X-Gateway-Secret", this.gsKey);
                    })
                    .retrieve()
                    // 2xx 가 아니면 에러
                    .onStatus(status -> !status.is2xxSuccessful(),
                              resp -> Mono.error(new RuntimeException("Invalid token")))
                    .toBodilessEntity()
                    // 검증 성공 시 요청 이어가기
                    .flatMap(resp -> chain.filter(exchange))
                    // 검증 실패 시 401
                    .onErrorResume(e -> {
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    });
            } else if(Objects.isNull(access) && Objects.nonNull(refresh)) {
            	// Access 리플레시
            	return webClient.post()
                    .uri("/token/refresh") // 토큰 검증 엔드포인트
                    .headers(h -> {
                        h.set("refreshToken", refreshToken);
                        h.set("X-Gateway-Secret", this.gsKey);
                    })
                    .retrieve()
                    // 2xx 가 아니면 에러
                    .onStatus(status -> !status.is2xxSuccessful(),
                              resp -> Mono.error(new RuntimeException("Invalid token")))
                    .toBodilessEntity()
                    // 검증 성공 시 요청 이어가기
                    .flatMap(resp -> {
                    	
                    	var setCookies = resp.getHeaders().get(HttpHeaders.SET_COOKIE);
                        if (setCookies != null) {
                            setCookies.forEach(c -> exchange.getResponse()
                                .getHeaders()
                                .add(HttpHeaders.SET_COOKIE, c));
                        }
                    	
                    	return chain.filter(exchange);
                    })
                    // 검증 실패 시 401
                    .onErrorResume(e -> {
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    });
            }else {
                // 액세스/리프레시 토큰이 모두 없는 경우: 로그인 페이지로 리다이렉트
                // - 303 See Other: POST/PUT 등도 안전하게 GET /auth/login 으로 전환
                // - 필요시 원래 요청 경로를 쿼리로 실어 로그인 후 되돌리기 가능
                String originalPath = request.getURI().getRawPath();
                String originalQuery = request.getURI().getRawQuery();
                String redirectTo = "/auth/login";
                if (originalPath != null && !originalPath.isEmpty()) {
                    String back = originalPath + (originalQuery != null ? "?" + originalQuery : "");
                    try {
						redirectTo = redirectTo + "?redirect=" + URLEncoder.encode(back, StandardCharsets.UTF_8.name());
					} catch (UnsupportedEncodingException e) { 
						e.printStackTrace();
						redirectTo = "/auth/login";
					}
                }

                ServerHttpResponse response = exchange.getResponse();
                response.setStatusCode(HttpStatus.SEE_OTHER);       // 303
                response.getHeaders().set("Location", redirectTo);  // 리다이렉트 대상
                return response.setComplete();
            }
        };
    }
}

