package jkt.gs.module.address.handler;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;

import jkt.gs.GlobalStore;
import jkt.gs.module.address.model.request.IpUpdateRequest;
import jkt.gs.util.RequestUtil;
import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;


@Component
@RequiredArgsConstructor
public class AddressHandler {
	
	private final GlobalStore store;
	
	///////////////////////////// 임시 ///////////////////////////
	public Mono<ServerResponse> findAddress(ServerRequest serverRequest){
		
		String ip = store.getIp();
		
		
		return ServerResponse.ok()
	            .contentType(MediaType.APPLICATION_JSON)			            
	            .bodyValue( ip == null ? "" : ip );
	}
	
	public Mono<ServerResponse> updateAddress(ServerRequest serverRequest){
		
		String ip = RequestUtil.getClientIp(serverRequest);
		
		
		///
		/// 검증처리 필요.
		///
		///
		
		store.updateIp(ip);
		
		return ServerResponse.ok()
	            .contentType(MediaType.APPLICATION_JSON)			            
	            .bodyValue("OK");
//		
//		return serverRequest.bodyToMono(IpUpdateRequest.class)				
//				.flatMap(request -> ServerResponse.ok()
//			            .contentType(MediaType.APPLICATION_JSON)			            
//			            .bodyValue("OK")
//				);
				
				
	}
}
