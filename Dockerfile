# ------------ STAGE 1: Build the JAR using Maven ------------
FROM maven:3.9.9-eclipse-temurin-17 AS builder

# Set working directory
WORKDIR /app

# Copy pom.xml first (helps with caching)
COPY pom.xml .

# Download dependencies (cached until pom.xml changes)
RUN mvn -e -B dependency:go-offline

# Copy the source code
COPY src ./src

# Package the application
RUN mvn clean package -DskipTests


# ------------ STAGE 2: Run the JAR --------------------------
FROM eclipse-temurin:17-jdk-jammy

WORKDIR /app

# Copy the built JAR from the builder stage
COPY --from=builder /app/target/*.jar app.jar

# Render provides dynamic port
ENV PORT=10000
EXPOSE $PORT

# Run the app with dynamic port
ENTRYPOINT ["sh", "-c", "java -jar app.jar --server.port=${PORT}"]
