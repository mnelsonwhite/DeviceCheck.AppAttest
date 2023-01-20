## Device Check App Attest Authentication

- https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity
- https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server

### Configuration



### Usage

1. Register Auth Handler

``` c#
var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddAuthentication()
    .AddAppAttest(); // <--- registers auth handler
builder.Services.AddAuthorization();
```

2. Setup the attestation service

``` c#
var app = builder.Build();

app.AddAppAttest(); // <--- setup attestation endpoint
app.UseAuthorization();
```

### Configuration

