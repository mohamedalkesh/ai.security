package com.aisec.backend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.client.RestClient;

import java.time.Duration;
import java.util.List;

@Configuration
public class RestClientConfig {

    @Bean
    public RestClient mlRestClient(AppProperties props) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofMillis(props.getMl().getConnectTimeoutMs()));
        factory.setReadTimeout(Duration.ofMillis(props.getMl().getReadTimeoutMs()));

        // The ML service (FastAPI/Starlette) sometimes streams large JSON
        // responses without an explicit Content-Type header. Spring then
        // defaults the response media type to application/octet-stream and
        // can't find a JSON converter, so PcapResult extraction fails with
        // "Error while extracting response ... content type [application/octet-stream]".
        // Teach the dedicated ML Jackson converter to also read octet-stream
        // so the body is always deserialised as JSON regardless of the header.
        MappingJackson2HttpMessageConverter jacksonOctetAware = new MappingJackson2HttpMessageConverter();
        jacksonOctetAware.setSupportedMediaTypes(List.of(
                MediaType.APPLICATION_JSON,
                MediaType.APPLICATION_OCTET_STREAM));

        return RestClient.builder()
                .baseUrl(props.getMl().getBaseUrl())
                .requestFactory(factory)
                .defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .messageConverters(converters -> converters.add(0, jacksonOctetAware))
                .build();
    }
}
