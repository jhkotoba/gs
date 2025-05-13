package jkt.gs.util;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.reactive.function.server.ServerRequest;

public class RequestUtil {
	
	/**
	 * 실제 클라이언트 IP를 추출
     * @param request
     * @return
     */
    public static String getClientIp(ServerRequest request) {
    	return getClientIp(request.exchange().getRequest());
    }
	
	/**
	 * 실제 클라이언트 IP를 추출
	 * @param request
	 * @return
	 */
    public static String getClientIp(ServerHttpRequest request) {
    	
        String[] headerNames = {
            "X-Forwarded-For",
            "Proxy-Client-IP",
            "WL-Proxy-Client-IP",
            "HTTP_CLIENT_IP",
            "HTTP_X_FORWARDED_FOR"
        };
        
        // 헤더에서 IP 추출 시도
        for (String header : headerNames) {
            String ip = request.getHeaders().getFirst(header);
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
            	if (ip.contains(",")) {
                    return ip.split(",")[0].trim();
                }else {
                	return ip.trim();
                }
            }
        }
        
        // 헤더에 IP가 없으면 RemoteAddress에서 직접 추출
        InetSocketAddress remoteAddress = request.getRemoteAddress();
        if (remoteAddress != null) {
            InetAddress address = remoteAddress.getAddress();
            if (address != null) {
            	return address.getHostAddress();
            }
        }
        
        // IP를 전혀 알 수 없는 경우 null 반환
        return null;
    }
}
