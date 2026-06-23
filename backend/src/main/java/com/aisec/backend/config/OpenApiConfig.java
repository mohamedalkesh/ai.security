package com.aisec.backend.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI / Swagger configuration.
 *
 * Exposes interactive API documentation at:
 *   - Swagger UI : /swagger-ui.html
 *   - OpenAPI doc: /v3/api-docs
 *
 * A global Bearer-JWT security scheme is registered so the "Authorize" button
 * in Swagger UI lets you paste a token obtained from POST /api/auth/login and
 * call every protected endpoint directly from the browser.
 */
@Configuration
public class OpenApiConfig {

    private static final String SCHEME_NAME = "bearerAuth";

    @Bean
    public OpenAPI madrsOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("MADRS API")
                        .description("Multi-dimensional Attack Detection and Response System — "
                                + "REST API for alerts, incidents, scans, reports, firewall and ML operations.")
                        .version("1.0.0")
                        .contact(new Contact().name("MADRS Team"))
                        .license(new License().name("Proprietary")))
                .addSecurityItem(new SecurityRequirement().addList(SCHEME_NAME))
                .components(new Components().addSecuritySchemes(SCHEME_NAME,
                        new SecurityScheme()
                                .name(SCHEME_NAME)
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("Paste the JWT returned by POST /api/auth/login")));
    }
}
