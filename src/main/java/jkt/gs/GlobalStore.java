package jkt.gs;

import java.util.concurrent.atomic.AtomicReference;

import org.springframework.stereotype.Component;

@Component
public class GlobalStore {

	private final AtomicReference<String> ipAddress = new AtomicReference<>();
	
	public void updateIp(String newIp) {
        ipAddress.set(newIp);
    }

    public String getIp() {
        return ipAddress.get();
    }
	
}
