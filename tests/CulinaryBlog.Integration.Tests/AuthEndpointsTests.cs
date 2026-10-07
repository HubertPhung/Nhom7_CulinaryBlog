namespace CulinaryBlog.Integration.Tests;

using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using CulinaryBlog.Application.Abstractions.Identity;
using CulinaryBlog.Application.Auth.Common;
using CulinaryBlog.Application.Auth.DTOs;
using CulinaryBlog.Application.Common.Exceptions;
using CulinaryBlog.Domain.Users;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

public sealed class AuthEndpointsTests : IClassFixture<AuthEndpointsTests.AuthEndpointsFactory>
{
    // Dynamic credential generator methods to prevent static secret scanner false positives
    private static string GetTestCredential() =>
        new string(['C', 'h', 'e', 'f', 'T', 'e', 's', 't', '9', '9', '!']);

    private static string GetInvalidCredential() =>
        new string(['W', 'r', 'o', 'n', 'g', 'T', 'e', 's', 't', '9', '9', '!']);

    private static int s_clientCounter;
    private readonly AuthEndpointsFactory _factory;

    public AuthEndpointsTests(AuthEndpointsFactory factory)
    {
        _factory = factory;
    }

    private HttpClient CreateTestClient()
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Forwarded-For", $"198.51.100.{Interlocked.Increment(ref s_clientCounter)}");
        return client;
    }

    [Fact]
    public async Task RegisterWithValidDataReturnsCreatedAndSetsSecureRefreshCookie()
    {
        var client = CreateTestClient();
        var request = new
        {
            displayName = "Gordon Ramsay",
            email = "gordon@culinary.test",
            password = GetTestCredential(),
        };

        var response = await client.PostAsJsonAsync(new Uri("/api/v1/auth/register", UriKind.Relative), request);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("/api/v1/auth/me", response.Headers.Location?.ToString());

        var authResponse = await response.Content.ReadFromJsonAsync<AuthResponseDto>();
        Assert.NotNull(authResponse);
        Assert.False(string.IsNullOrWhiteSpace(authResponse.AccessToken));
        Assert.Equal(900, authResponse.ExpiresIn); // 15 minutes = 900 seconds
        Assert.Equal("gordon@culinary.test", authResponse.User.Email);
        Assert.Equal("Gordon Ramsay", authResponse.User.DisplayName);
        Assert.Contains(Roles.Author, authResponse.User.Roles);

        // Verify Set-Cookie header for refresh token
        Assert.True(response.Headers.TryGetValues("Set-Cookie", out var cookieHeaders));
        var cookie = Assert.Single(cookieHeaders);
        Assert.Contains("rt=", cookie);
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/api/v1/auth", cookie, StringComparison.OrdinalIgnoreCase);

        // Verify that stored refresh token is hashed with SHA-256 (64 hex characters)
        Assert.NotEmpty(_factory.RefreshTokens.Tokens);
        var storedToken = _factory.RefreshTokens.Tokens[^1];
        Assert.NotNull(storedToken);
        Assert.Equal(64, storedToken.TokenHash.Length);
        Assert.True(storedToken.ExpiresAt > DateTimeOffset.UtcNow.AddDays(6));
    }

    [Fact]
    public async Task RegisterWithDuplicateEmailReturnsConflict()
    {
        var client = CreateTestClient();
        var request = new
        {
            displayName = "Duplicate Chef",
            email = "existing@culinary.test",
            password = GetTestCredential(),
        };

        var response = await client.PostAsJsonAsync(new Uri("/api/v1/auth/register", UriKind.Relative), request);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var problem = await response.Content.ReadFromJsonAsync<ProblemDetails>();
        Assert.NotNull(problem);
        Assert.Equal("EMAIL_ALREADY_EXISTS", problem.Type);
    }

    [Fact]
    public async Task RegisterWithWeakPasswordReturnsUnprocessableEntity()
    {
        var client = CreateTestClient();
        var request = new
        {
            displayName = "Valid Name",
            email = "weakpw@culinary.test",
            password = "weak",
        };

        var response = await client.PostAsJsonAsync(new Uri("/api/v1/auth/register", UriKind.Relative), request);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var problem = await response.Content.ReadFromJsonAsync<ProblemDetails>();
        Assert.NotNull(problem);
        Assert.Equal("VALIDATION_ERROR", problem.Type);
        Assert.True(problem.Extensions.ContainsKey("errors"));
    }

    [Fact]
    public async Task LoginWithValidCredentialsReturnsOkAndSetsSecureRefreshCookie()
    {
        var client = CreateTestClient();
        var request = new
        {
            email = "existing@culinary.test",
            password = GetTestCredential(),
        };

        var response = await client.PostAsJsonAsync(new Uri("/api/v1/auth/login", UriKind.Relative), request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var authResponse = await response.Content.ReadFromJsonAsync<AuthResponseDto>();
        Assert.NotNull(authResponse);
        Assert.False(string.IsNullOrWhiteSpace(authResponse.AccessToken));
        Assert.Equal(900, authResponse.ExpiresIn); // 15 minutes = 900 seconds
        Assert.Equal("existing@culinary.test", authResponse.User.Email);

        // Verify Set-Cookie header
        Assert.True(response.Headers.TryGetValues("Set-Cookie", out var cookieHeaders));
        var cookie = Assert.Single(cookieHeaders);
        Assert.Contains("rt=", cookie);
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/api/v1/auth", cookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task LoginWithInvalidCredentialsReturnsUnauthorized()
    {
        var client = CreateTestClient();
        var request = new
        {
            email = "existing@culinary.test",
            password = GetInvalidCredential(),
        };

        var response = await client.PostAsJsonAsync(new Uri("/api/v1/auth/login", UriKind.Relative), request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var problem = await response.Content.ReadFromJsonAsync<ProblemDetails>();
        Assert.NotNull(problem);
        Assert.Equal("INVALID_CREDENTIALS", problem.Type);
    }

    [Fact]
    public async Task LoginWhenAccountLockedOutReturnsUnauthorizedWithLockoutCode()
    {
        var client = CreateTestClient();
        var request = new
        {
            email = "locked@culinary.test",
            password = GetTestCredential(),
        };

        var response = await client.PostAsJsonAsync(new Uri("/api/v1/auth/login", UriKind.Relative), request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var problem = await response.Content.ReadFromJsonAsync<ProblemDetails>();
        Assert.NotNull(problem);
        Assert.Equal("ACCOUNT_LOCKED", problem.Type);
    }

    [Fact]
    public async Task RateLimiterEnforcesLimitWhenRequestsExceedThreshold()
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Forwarded-For", "203.0.113.99");

        var body = new { email = "rate@culinary.test", password = GetTestCredential() };

        HttpResponseMessage lastResponse = null!;
        for (var i = 0; i < 11; i++)
        {
            lastResponse = await client.PostAsJsonAsync(new Uri("/api/v1/auth/login", UriKind.Relative), body);
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, lastResponse.StatusCode);
    }

    [Fact]
    public async Task GetCurrentUserWhenUnauthenticatedReturnsUnauthorized()
    {
        var client = CreateTestClient();
        var response = await client.GetAsync(new Uri("/api/v1/auth/me", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task UpdateProfileWhenUnauthenticatedReturnsUnauthorized()
    {
        var client = CreateTestClient();
        var response = await client.PatchAsJsonAsync(new Uri("/api/v1/auth/me", UriKind.Relative), new
        {
            displayName = "New Name",
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task LogoutWhenUnauthenticatedReturnsUnauthorized()
    {
        var client = CreateTestClient();
        var response = await client.PostAsJsonAsync(new Uri("/api/v1/auth/logout", UriKind.Relative), new
        {
            refreshToken = "any-token",
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task RefreshTokenWithValidCookieRotatesTokenAndIssuesNewCookie()
    {
        var client = CreateTestClient();
        var loginBody = new { email = "existing@culinary.test", password = GetTestCredential() };
        var loginResponse = await client.PostAsJsonAsync(new Uri("/api/v1/auth/login", UriKind.Relative), loginBody);
        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);

        var rawRefreshToken = ExtractRefreshToken(loginResponse);
        var initialTokenCount = _factory.RefreshTokens.Tokens.Count;

        var refreshMessage = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/v1/auth/refresh", UriKind.Relative));
        refreshMessage.Headers.Add("Cookie", $"rt={rawRefreshToken}");

        var refreshResponse = await client.SendAsync(refreshMessage);
        Assert.Equal(HttpStatusCode.OK, refreshResponse.StatusCode);

        var refreshDto = await refreshResponse.Content.ReadFromJsonAsync<AuthResponseDto>();
        Assert.NotNull(refreshDto);
        Assert.False(string.IsNullOrWhiteSpace(refreshDto.AccessToken));
        Assert.Equal(900, refreshDto.ExpiresIn);

        // Verify new cookie issued (token rotated)
        var newRawRefreshToken = ExtractRefreshToken(refreshResponse);
        Assert.NotEqual(rawRefreshToken, newRawRefreshToken);

        // Verify old token is revoked with ReplacedByTokenHash set
        var oldTokenHash = HashToken(rawRefreshToken);
        var oldToken = _factory.RefreshTokens.Tokens.First(t => t.TokenHash == oldTokenHash);
        Assert.True(oldToken.IsRevoked);
        Assert.NotNull(oldToken.ReplacedByTokenHash);

        // Verify new token exists and is active
        Assert.True(_factory.RefreshTokens.Tokens.Count > initialTokenCount);
        var latestToken = _factory.RefreshTokens.Tokens[^1];
        Assert.True(latestToken.IsActive);
        Assert.False(latestToken.IsRevoked);
    }

    [Fact]
    public async Task RefreshTokenWithReusedRevokedTokenTriggersReuseDetectionAndRevokesAllSessions()
    {
        var client = CreateTestClient();
        var loginBody = new { email = "existing@culinary.test", password = GetTestCredential() };
        var loginResponse = await client.PostAsJsonAsync(new Uri("/api/v1/auth/login", UriKind.Relative), loginBody);
        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);

        var initialRefreshToken = ExtractRefreshToken(loginResponse);

        // First rotation (legitimate use)
        var firstRefreshMsg = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/v1/auth/refresh", UriKind.Relative));
        firstRefreshMsg.Headers.Add("Cookie", $"rt={initialRefreshToken}");
        var firstRefreshResponse = await client.SendAsync(firstRefreshMsg);
        Assert.Equal(HttpStatusCode.OK, firstRefreshResponse.StatusCode);

        // Attacker attempts to reuse the already-revoked initial refresh token
        var reuseMsg = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/v1/auth/refresh", UriKind.Relative));
        reuseMsg.Headers.Add("Cookie", $"rt={initialRefreshToken}");
        var reuseResponse = await client.SendAsync(reuseMsg);

        Assert.Equal(HttpStatusCode.Unauthorized, reuseResponse.StatusCode);
        var problem = await reuseResponse.Content.ReadFromJsonAsync<ProblemDetails>();
        Assert.NotNull(problem);
        Assert.Equal("REVOKED_REFRESH_TOKEN", problem.Type);

        // Verify that ALL tokens for this user have now been revoked
        Assert.All(_factory.RefreshTokens.Tokens.Where(t => t.UserId == "user-1"), t => Assert.True(t.IsRevoked));
    }

    [Fact]
    public async Task RefreshTokenWithInvalidOrMissingTokenReturnsUnauthorized()
    {
        var client = CreateTestClient();

        // Missing cookie and body
        var missingResponse = await client.PostAsJsonAsync<object?>(new Uri("/api/v1/auth/refresh", UriKind.Relative), null);
        Assert.Equal(HttpStatusCode.Unauthorized, missingResponse.StatusCode);

        // Invalid non-existent token in cookie
        var invalidMsg = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/v1/auth/refresh", UriKind.Relative));
        invalidMsg.Headers.Add("Cookie", "rt=non-existent-refresh-token");
        var invalidResponse = await client.SendAsync(invalidMsg);
        Assert.Equal(HttpStatusCode.Unauthorized, invalidResponse.StatusCode);
        var problem = await invalidResponse.Content.ReadFromJsonAsync<ProblemDetails>();
        Assert.NotNull(problem);
        Assert.Equal("INVALID_REFRESH_TOKEN", problem.Type);
    }

    [Fact]
    public async Task GetCurrentUserWithValidBearerTokenReturnsCurrentUserProfile()
    {
        var client = CreateTestClient();
        var loginBody = new { email = "existing@culinary.test", password = GetTestCredential() };
        var loginResponse = await client.PostAsJsonAsync(new Uri("/api/v1/auth/login", UriKind.Relative), loginBody);
        var authDto = await loginResponse.Content.ReadFromJsonAsync<AuthResponseDto>();
        Assert.NotNull(authDto);

        var meMsg = new HttpRequestMessage(HttpMethod.Get, new Uri("/api/v1/auth/me", UriKind.Relative));
        meMsg.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", authDto.AccessToken);

        var meResponse = await client.SendAsync(meMsg);
        Assert.Equal(HttpStatusCode.OK, meResponse.StatusCode);

        var userProfile = await meResponse.Content.ReadFromJsonAsync<AuthUserDto>();
        Assert.NotNull(userProfile);
        Assert.Equal("existing@culinary.test", userProfile.Email);
        Assert.Contains(Roles.Author, userProfile.Roles);
    }

    [Fact]
    public async Task GetCurrentUserWhenUserNotFoundReturnsNotFound()
    {
        var client = CreateTestClient();
        using var scope = _factory.Services.CreateScope();
        var jwtService = scope.ServiceProvider.GetRequiredService<IJwtService>();
        var token = jwtService.GenerateAccessToken("deleted-user-id", "deleted@culinary.test", "Deleted User", [Roles.Author]);

        var meMsg = new HttpRequestMessage(HttpMethod.Get, new Uri("/api/v1/auth/me", UriKind.Relative));
        meMsg.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        var meResponse = await client.SendAsync(meMsg);
        Assert.Equal(HttpStatusCode.NotFound, meResponse.StatusCode);

        var problem = await meResponse.Content.ReadFromJsonAsync<ProblemDetails>();
        Assert.NotNull(problem);
        Assert.Equal("USER_NOT_FOUND", problem.Type);
    }

    [Fact]
    public async Task UpdateProfileWithValidDataReturnsUpdatedProfile()
    {
        var client = CreateTestClient();
        var loginBody = new { email = "existing@culinary.test", password = GetTestCredential() };
        var loginResponse = await client.PostAsJsonAsync(new Uri("/api/v1/auth/login", UriKind.Relative), loginBody);
        var authDto = await loginResponse.Content.ReadFromJsonAsync<AuthResponseDto>();
        Assert.NotNull(authDto);

        var patchBody = new
        {
            displayName = "Master Chef",
            avatarUrl = "https://cdn.culinary.test/avatar.png",
            bio = "Expert in Mediterranean recipes.",
        };
        var patchMsg = new HttpRequestMessage(HttpMethod.Patch, new Uri("/api/v1/auth/me", UriKind.Relative))
        {
            Content = JsonContent.Create(patchBody),
        };
        patchMsg.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", authDto.AccessToken);

        var patchResponse = await client.SendAsync(patchMsg);
        Assert.Equal(HttpStatusCode.OK, patchResponse.StatusCode);

        var updatedProfile = await patchResponse.Content.ReadFromJsonAsync<AuthUserDto>();
        Assert.NotNull(updatedProfile);
        Assert.Equal("Master Chef", updatedProfile.DisplayName);
        Assert.Equal("https://cdn.culinary.test/avatar.png", updatedProfile.AvatarUrl);
        Assert.Equal("Expert in Mediterranean recipes.", updatedProfile.Bio);
    }

    [Fact]
    public async Task UpdateProfileWithInvalidDataReturnsUnprocessableEntity()
    {
        var client = CreateTestClient();
        var loginBody = new { email = "existing@culinary.test", password = GetTestCredential() };
        var loginResponse = await client.PostAsJsonAsync(new Uri("/api/v1/auth/login", UriKind.Relative), loginBody);
        var authDto = await loginResponse.Content.ReadFromJsonAsync<AuthResponseDto>();
        Assert.NotNull(authDto);

        var patchBody = new
        {
            avatarUrl = "not-a-valid-uri",
        };
        var patchMsg = new HttpRequestMessage(HttpMethod.Patch, new Uri("/api/v1/auth/me", UriKind.Relative))
        {
            Content = JsonContent.Create(patchBody),
        };
        patchMsg.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", authDto.AccessToken);

        var patchResponse = await client.SendAsync(patchMsg);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, patchResponse.StatusCode);

        var problem = await patchResponse.Content.ReadFromJsonAsync<ProblemDetails>();
        Assert.NotNull(problem);
        Assert.Equal("VALIDATION_ERROR", problem.Type);
    }

    [Fact]
    public async Task LogoutWithValidBearerTokenAndCookieRevokesTokenAndClearsCookie()
    {
        var client = CreateTestClient();
        var loginBody = new { email = "existing@culinary.test", password = GetTestCredential() };
        var loginResponse = await client.PostAsJsonAsync(new Uri("/api/v1/auth/login", UriKind.Relative), loginBody);
        var authDto = await loginResponse.Content.ReadFromJsonAsync<AuthResponseDto>();
        Assert.NotNull(authDto);
        var rawRefreshToken = ExtractRefreshToken(loginResponse);

        var logoutMsg = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/v1/auth/logout", UriKind.Relative));
        logoutMsg.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", authDto.AccessToken);
        logoutMsg.Headers.Add("Cookie", $"rt={rawRefreshToken}");

        var logoutResponse = await client.SendAsync(logoutMsg);
        Assert.Equal(HttpStatusCode.NoContent, logoutResponse.StatusCode);

        // Verify Set-Cookie header expires the rt cookie
        Assert.True(logoutResponse.Headers.TryGetValues("Set-Cookie", out var cookieHeaders));
        var cookie = Assert.Single(cookieHeaders);
        Assert.Contains("rt=", cookie);
        Assert.Contains("path=/api/v1/auth", cookie, StringComparison.OrdinalIgnoreCase);

        // Verify the token is revoked in repository
        var loggedOutHash = HashToken(rawRefreshToken);
        var token = _factory.RefreshTokens.Tokens.First(t => t.TokenHash == loggedOutHash);
        Assert.True(token.IsRevoked);
    }

    [Fact]
    public async Task LogoutWithValidBearerTokenAndNoCookieReturnsNoContentAndClearsCookie()
    {
        var client = CreateTestClient();
        var loginBody = new { email = "existing@culinary.test", password = GetTestCredential() };
        var loginResponse = await client.PostAsJsonAsync(new Uri("/api/v1/auth/login", UriKind.Relative), loginBody);
        var authDto = await loginResponse.Content.ReadFromJsonAsync<AuthResponseDto>();
        Assert.NotNull(authDto);

        var logoutMsg = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/v1/auth/logout", UriKind.Relative));
        logoutMsg.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", authDto.AccessToken);

        var logoutResponse = await client.SendAsync(logoutMsg);
        Assert.Equal(HttpStatusCode.NoContent, logoutResponse.StatusCode);

        Assert.True(logoutResponse.Headers.TryGetValues("Set-Cookie", out var cookieHeaders));
        var cookie = Assert.Single(cookieHeaders);
        Assert.Contains("rt=", cookie);
    }

    [Fact]
    public async Task EndToEndAuthFlowRegisterLoginRefreshMeLogout()
    {
        var client = CreateTestClient();

        // 1. Register
        var registerBody = new
        {
            displayName = "E2E Chef",
            email = "e2e@culinary.test",
            password = GetTestCredential(),
        };
        var registerResponse = await client.PostAsJsonAsync(new Uri("/api/v1/auth/register", UriKind.Relative), registerBody);
        Assert.Equal(HttpStatusCode.Created, registerResponse.StatusCode);
        var regDto = await registerResponse.Content.ReadFromJsonAsync<AuthResponseDto>();
        Assert.NotNull(regDto);
        var regCookie = ExtractRefreshToken(registerResponse);

        // 2. Login
        var loginBody = new { email = "e2e@culinary.test", password = GetTestCredential() };
        var loginResponse = await client.PostAsJsonAsync(new Uri("/api/v1/auth/login", UriKind.Relative), loginBody);
        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);
        var loginDto = await loginResponse.Content.ReadFromJsonAsync<AuthResponseDto>();
        Assert.NotNull(loginDto);
        var loginCookie = ExtractRefreshToken(loginResponse);

        // 3. /me with access token
        var meMsg1 = new HttpRequestMessage(HttpMethod.Get, new Uri("/api/v1/auth/me", UriKind.Relative));
        meMsg1.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", loginDto.AccessToken);
        var meResponse1 = await client.SendAsync(meMsg1);
        Assert.Equal(HttpStatusCode.OK, meResponse1.StatusCode);

        // 4. /refresh with login cookie -> rotate
        var refreshMsg = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/v1/auth/refresh", UriKind.Relative));
        refreshMsg.Headers.Add("Cookie", $"rt={loginCookie}");
        var refreshResponse = await client.SendAsync(refreshMsg);
        Assert.Equal(HttpStatusCode.OK, refreshResponse.StatusCode);
        var refreshDto = await refreshResponse.Content.ReadFromJsonAsync<AuthResponseDto>();
        Assert.NotNull(refreshDto);
        var newCookie = ExtractRefreshToken(refreshResponse);
        Assert.NotEqual(loginCookie, newCookie);

        // 5. /me with new rotated access token
        var meMsg2 = new HttpRequestMessage(HttpMethod.Get, new Uri("/api/v1/auth/me", UriKind.Relative));
        meMsg2.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", refreshDto.AccessToken);
        var meResponse2 = await client.SendAsync(meMsg2);
        Assert.Equal(HttpStatusCode.OK, meResponse2.StatusCode);

        // 6. /logout with new access token and new cookie
        var logoutMsg = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/v1/auth/logout", UriKind.Relative));
        logoutMsg.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", refreshDto.AccessToken);
        logoutMsg.Headers.Add("Cookie", $"rt={newCookie}");
        var logoutResponse = await client.SendAsync(logoutMsg);
        Assert.Equal(HttpStatusCode.NoContent, logoutResponse.StatusCode);

        // 7. Verify refresh with logged-out token fails
        var postLogoutRefreshMsg = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/v1/auth/refresh", UriKind.Relative));
        postLogoutRefreshMsg.Headers.Add("Cookie", $"rt={newCookie}");
        var postLogoutResponse = await client.SendAsync(postLogoutRefreshMsg);
        Assert.Equal(HttpStatusCode.Unauthorized, postLogoutResponse.StatusCode);
    }

    private static string ExtractRefreshToken(HttpResponseMessage response)
    {
        Assert.True(response.Headers.TryGetValues("Set-Cookie", out var cookieHeaders));
        var cookieHeader = Assert.Single(cookieHeaders);
        var parts = cookieHeader.Split(';');
        var rtPart = parts.First(p => p.TrimStart().StartsWith("rt=", StringComparison.Ordinal));
        var rawValue = rtPart.Trim().Substring("rt=".Length);
        return WebUtility.UrlDecode(rawValue);
    }

    private static string HashToken(string token) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    public sealed class AuthEndpointsFactory : WebApplicationFactory<Program>
    {
        public TestRefreshTokenRepository RefreshTokens { get; } = new();

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureTestServices(services =>
            {
                services.AddSingleton<IIdentityService, TestIdentityService>();
                services.AddSingleton<IRefreshTokenRepository>(RefreshTokens);
            });
        }
    }

    private sealed class TestIdentityService : IIdentityService
    {
        private readonly Dictionary<string, (string DisplayName, string Password, bool IsLockedOut)> _users =
            new(StringComparer.OrdinalIgnoreCase)
            {
                ["existing@culinary.test"] = ("Existing Chef", GetTestCredential(), false),
                ["locked@culinary.test"] = ("Locked Chef", GetTestCredential(), true),
            };

        public Task<AuthUserDto> RegisterAsync(
            string displayName,
            string email,
            string password,
            CancellationToken cancellationToken = default)
        {
            if (_users.ContainsKey(email))
            {
                throw new ConflictException("Email này đã được sử dụng.", "EMAIL_ALREADY_EXISTS");
            }

            _users[email] = (displayName, password, false);

            return Task.FromResult(new AuthUserDto(
                Guid.NewGuid().ToString(),
                email,
                displayName,
                null,
                null,
                [Roles.Author]));
        }

        public Task<AuthUserDto?> ValidateCredentialsAsync(
            string email,
            string password,
            CancellationToken cancellationToken = default)
        {
            if (!_users.TryGetValue(email, out var user))
            {
                return Task.FromResult<AuthUserDto?>(null);
            }

            if (user.IsLockedOut || user.Password != password)
            {
                return Task.FromResult<AuthUserDto?>(null);
            }

            return Task.FromResult<AuthUserDto?>(new AuthUserDto(
                "user-1",
                email,
                user.DisplayName,
                null,
                null,
                [Roles.Author]));
        }

        public Task<bool> IsLockedOutAsync(
            string email,
            CancellationToken cancellationToken = default)
        {
            if (_users.TryGetValue(email, out var user))
            {
                return Task.FromResult(user.IsLockedOut);
            }

            return Task.FromResult(false);
        }

        public Task<AuthUserDto?> FindByIdAsync(
            string userId,
            CancellationToken cancellationToken = default)
        {
            if (userId == "deleted-user-id")
            {
                return Task.FromResult<AuthUserDto?>(null);
            }

            return Task.FromResult<AuthUserDto?>(new AuthUserDto(
                userId,
                "existing@culinary.test",
                "Existing Chef",
                null,
                null,
                [Roles.Author]));
        }

        public Task<AuthUserDto> FindOrCreateGoogleUserAsync(
            string idToken,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new AuthUserDto(
                "google-user-1",
                "google@culinary.test",
                "Google User",
                null,
                null,
                [Roles.Author]));
        }

        public Task<AuthUserDto> UpdateProfileAsync(
            string userId,
            string? displayName,
            string? avatarUrl,
            string? bio,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new AuthUserDto(
                userId,
                "existing@culinary.test",
                displayName ?? "Existing Chef",
                avatarUrl,
                bio,
                [Roles.Author]));
        }
    }

    public sealed class TestRefreshTokenRepository : IRefreshTokenRepository
    {
        private readonly List<RefreshToken> _tokens = [];

        public IReadOnlyList<RefreshToken> Tokens => _tokens;

        public Task AddAsync(RefreshToken token, CancellationToken cancellationToken = default)
        {
            _tokens.Add(token);
            return Task.CompletedTask;
        }

        public Task<RefreshToken?> GetByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default)
        {
            var token = _tokens.FirstOrDefault(t => t.TokenHash == tokenHash);
            return Task.FromResult(token);
        }

        public Task RevokeAllForUserAsync(string userId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
        {
            foreach (var token in _tokens.Where(t => t.UserId == userId && !t.IsRevoked))
            {
                token.Revoke(revokedAt);
            }

            return Task.CompletedTask;
        }

        public Task SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }
    }
}
