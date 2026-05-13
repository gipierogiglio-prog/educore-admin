FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app
COPY AdminApi.csproj .
RUN dotnet restore AdminApi.csproj
COPY . .
RUN dotnet publish AdminApi.csproj -c Release -o /out
RUN mkdir -p /out/wwwroot && cp frontend/index.html /out/wwwroot/index.html

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
EXPOSE 5001
COPY --from=build /out .
ENV ASPNETCORE_URLS=http://+:5001
ENV ASPNETCORE_ENVIRONMENT=Production
ENTRYPOINT ["dotnet", "AdminApi.dll"]
