FROM maven:3.8.3-openjdk-17-slim AS builder

WORKDIR /app

COPY pom.xml .
RUN mvn dependency:go-offline -B

COPY src ./src
RUN mvn clean package -B


FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

RUN addgroup -g 1000 -S appgroup && \
    adduser -u 1000 -S appuser -G appgroup

COPY --from=0 --chown=appuser:appgroup /app/target/*.jar api.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "api.jar"]
