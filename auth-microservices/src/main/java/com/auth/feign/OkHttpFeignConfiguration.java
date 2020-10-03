
package com.auth.feign;

import java.util.concurrent.TimeUnit;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.cloud.openfeign.FeignAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import feign.Feign;
import feign.codec.Encoder;
import feign.form.FormEncoder;
import okhttp3.ConnectionPool;
import okhttp3.OkHttpClient;

@Configuration
@ConditionalOnClass(Feign.class)
@AutoConfigureBefore(FeignAutoConfiguration.class)
public class OkHttpFeignConfiguration {

	@Bean
	public Encoder encoder() {
		return new FormEncoder();
	}
	
	@Bean
	public OkHttpClient okHttpClient() {
		return new OkHttpClient.Builder().connectTimeout(10, TimeUnit.SECONDS).readTimeout(10, TimeUnit.SECONDS)
				.writeTimeout(10, TimeUnit.SECONDS).retryOnConnectionFailure(true).connectionPool(connectionPool())
				.build();
	}

	@Bean
	public ConnectionPool connectionPool() {
		return new ConnectionPool(50, 5, TimeUnit.MINUTES);
	}
}
