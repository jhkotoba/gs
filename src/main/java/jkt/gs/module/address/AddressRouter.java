package jkt.gs.module.address;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

import jkt.gs.module.address.handler.AddressHandler;

@Configuration
public class AddressRouter {

	
	@Bean
	protected RouterFunction<ServerResponse> address(AddressHandler addressHandler){
		
		return RouterFunctions
			.route(RequestPredicates.POST("/address/find")
				.and(RequestPredicates.accept(MediaType.APPLICATION_JSON)), addressHandler::findAddress)
			.andRoute(RequestPredicates.POST("/address/update")
				.and(RequestPredicates.accept(MediaType.APPLICATION_JSON)), addressHandler::updateAddress);			
	}
}
