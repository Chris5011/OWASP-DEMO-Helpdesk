FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY lab.csproj .
RUN dotnet restore
COPY . .
RUN dotnet publish -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:8.0
# iputils-ping: the admin diagnostics (cmdi challenge) shells out to `ping`.
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app .
EXPOSE 5001
ENTRYPOINT ["dotnet", "lab.dll"]
