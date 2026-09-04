FROM eclipse-temurin:21-jdk AS builder
WORKDIR /app
COPY gradlew build.gradle settings.gradle ./
COPY gradle gradle
RUN chmod +x gradlew && ./gradlew --version --console=plain
COPY src src
RUN ./gradlew bootJar --no-daemon --console=plain

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=builder /app/build/libs/*.jar app.jar
COPY docker-entrypoint.sh .
RUN chmod +x docker-entrypoint.sh
ENV SCORE_TOKEN=""
ENV DB_PATH="/app/data/rosterly.db"
EXPOSE 5000
ENTRYPOINT ["./docker-entrypoint.sh"]
