# syntax=docker/dockerfile:1
# Build context: repository root  ->  docker build -f src/SecureGateway.Gateway/Dockerfile .

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Restore in a separate layer so that dependency downloads are cached across source changes.
COPY Directory.Build.props Directory.Packages.props ./
COPY src/SecureGateway.Domain/SecureGateway.Domain.csproj                 src/SecureGateway.Domain/
COPY src/SecureGateway.Application/SecureGateway.Application.csproj       src/SecureGateway.Application/
COPY src/SecureGateway.Infrastructure/SecureGateway.Infrastructure.csproj src/SecureGateway.Infrastructure/
COPY src/SecureGateway.Gateway/SecureGateway.Gateway.csproj               src/SecureGateway.Gateway/
RUN dotnet restore src/SecureGateway.Gateway/SecureGateway.Gateway.csproj

COPY src/ src/
RUN dotnet publish src/SecureGateway.Gateway/SecureGateway.Gateway.csproj \
    -c Release -o /app/publish --no-restore /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_GCServer=1
COPY --from=build /app/publish .
# Built-in non-root user shipped with the official .NET 8 images.
USER app
EXPOSE 8080
ENTRYPOINT ["dotnet", "SecureGateway.Gateway.dll"]
