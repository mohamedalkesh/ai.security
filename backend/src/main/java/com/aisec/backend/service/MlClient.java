package com.aisec.backend.service;

import com.aisec.backend.dto.FlowRequest;
import com.aisec.backend.dto.ModelInfo;
import com.aisec.backend.dto.PcapResult;
import com.aisec.backend.dto.PredictionResult;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StreamUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

@Service
public class MlClient {

    private static final Logger log = LoggerFactory.getLogger(MlClient.class);
    private final RestClient ml;
    private final ObjectMapper mapper;

    public MlClient(RestClient mlRestClient, ObjectMapper mapper) {
        this.ml = mlRestClient;
        this.mapper = mapper;
    }

    public Map<String, Object> health() {
        return ml.get()
                .uri("/health")
                .retrieve()
                .body(Map.class);
    }

    public ModelInfo modelInfo() {
        return ml.get()
                .uri("/api/model/info")
                .retrieve()
                .body(ModelInfo.class);
    }

    public PredictionResult predictFlow(FlowRequest req) {
        return ml.post()
                .uri("/api/predict/flow")
                .contentType(MediaType.APPLICATION_JSON)
                .body(req)
                .retrieve()
                .body(PredictionResult.class);
    }

    public PcapResult predictPcap(MultipartFile file) throws IOException {
        Path tmp = Files.createTempFile("mlclient-upload-", ".pcap");
        try {
            file.transferTo(tmp.toFile());
            return predictPcap(tmp, file.getOriginalFilename());
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    public PcapResult predictPcap(Path file, String originalName) {
        FileSystemResource resource = new FileSystemResource(file) {
            @Override
            public String getFilename() {
                return originalName;
            }
        };
        return sendPcapResource(resource, originalName);
    }

    private PcapResult sendPcapResource(org.springframework.core.io.Resource resource, String filename) {
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("file", resource);

        log.info("Forwarding PCAP to ML service: {}", filename);

        return ml.post()
                .uri("/api/predict/pcap")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(body)
                .exchange((request, response) -> {
                    try {
                        String responseBody = StreamUtils.copyToString(response.getBody(), java.nio.charset.StandardCharsets.UTF_8);
                        if (!response.getStatusCode().is2xxSuccessful()) {
                            String head = responseBody.substring(0, Math.min(responseBody.length(), 500));
                            throw new IllegalStateException("ML service returned HTTP " + response.getStatusCode().value() + ": " + head);
                        }
                        return mapper.readValue(responseBody, PcapResult.class);
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                });
    }

    // ─── Live Monitor Proxy ───────────────────────────────────────────

    @SuppressWarnings("unchecked")
    public java.util.List<Map<String, Object>> monitorInterfaces() {
        return ml.get()
                .uri("/api/monitor/interfaces")
                .retrieve()
                .body(java.util.List.class);
    }

    public Map<String, Object> monitorStart(String iface) {
        return ml.post()
                .uri("/api/monitor/start")
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("interface", iface))
                .retrieve()
                .body(Map.class);
    }

    public Map<String, Object> monitorStop() {
        return ml.post()
                .uri("/api/monitor/stop")
                .retrieve()
                .body(Map.class);
    }

    public Map<String, Object> monitorStatus() {
        return ml.get()
                .uri("/api/monitor/status")
                .retrieve()
                .body(Map.class);
    }

    @SuppressWarnings("unchecked")
    public java.util.List<Map<String, Object>> monitorDrain(int limit) {
        Map<String, Object> resp = ml.post()
                .uri("/api/monitor/drain?limit=" + limit)
                .retrieve()
                .body(Map.class);
        return (java.util.List<Map<String, Object>>) resp.get("detections");
    }
}
