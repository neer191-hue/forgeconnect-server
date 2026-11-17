FROM eclipse-temurin:21-jdk
WORKDIR /app
COPY AuthServer.java .
CMD ["java", "AuthServer.java"]
