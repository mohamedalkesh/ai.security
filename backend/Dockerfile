FROM eclipse-temurin:21-jdk

WORKDIR /app

COPY . .

RUN chmod +x mvnw || true

RUN ./mvnw clean package -DskipTests || mvn clean package -DskipTests

EXPOSE 8080

CMD ["java","-jar","target/backend-1.0.0.jar"]

