# syntax=docker/dockerfile:1
# Shared image definition for the sample downstream services.
# docker build -f samples/Dockerfile --build-arg SERVICE_PROJECT=SecureGateway.Samples.AccountsService .

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG SERVICE_PROJECT
WORKDIR /src
COPY Directory.Build.props Directory.Packages.props ./
COPY samples/${SERVICE_PROJECT}/${SERVICE_PROJECT}.csproj samples/${SERVICE_PROJECT}/
RUN dotnet restore samples/${SERVICE_PROJECT}/${SERVICE_PROJECT}.csproj
COPY samples/${SERVICE_PROJECT}/ samples/${SERVICE_PROJECT}/
RUN dotnet publish samples/${SERVICE_PROJECT}/${SERVICE_PROJECT}.csproj \
    -c Release -o /app/publish --no-restore /p:UseAppHost=false \
 && mv /app/publish/${SERVICE_PROJECT}.dll /app/publish/service.dll \
 && mv /app/publish/${SERVICE_PROJECT}.deps.json /app/publish/service.deps.json \
 && mv /app/publish/${SERVICE_PROJECT}.runtimeconfig.json /app/publish/service.runtimeconfig.json

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
ENV ASPNETCORE_HTTP_PORTS=8080
COPY --from=build /app/publish .
USER app
EXPOSE 8080
ENTRYPOINT ["dotnet", "service.dll"]
