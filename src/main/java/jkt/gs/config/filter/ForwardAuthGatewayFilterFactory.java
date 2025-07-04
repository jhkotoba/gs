package jkt.gs.config.filter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
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
	public ForwardAuthGatewayFilterFactory(WebClient.Builder builder, @Value("${gateway.uri.oe}") String oeUri) {
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
            // Cookie 에서 토큰 추출
        	HttpCookie cookie = exchange.getRequest()
            	.getCookies()
            	.getFirst("accessToken");
            
            if (cookie == null) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
            String token = cookie.getValue();

            // 인증 체크 호출
            return webClient.post()
                .uri("/token/check") // 토큰 검증 엔드포인트
                .headers(h -> {
                    h.setBearerAuth(token);
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
        };
    }
}

