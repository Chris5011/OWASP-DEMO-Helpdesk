FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src ./src
RUN mvn -q -B package

FROM eclipse-temurin:21-jre
# iputils-ping so the diagnostics (command-injection) feature has a real base command
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/target/lab.jar app.jar
EXPOSE 7000
CMD ["java", "-jar", "app.jar"]
