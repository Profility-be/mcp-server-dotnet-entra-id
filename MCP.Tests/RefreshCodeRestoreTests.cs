using MCP.Models;
using Profility.MCP.Services.TokenStore;

namespace MCP.Tests;

/// <summary>
/// Guards the code-restore path used when Entra ID is unreachable during a refresh.
///
/// The token endpoint consumes a single-use code before it calls Entra ID. When that call fails
/// because Entra could not be reached, the endpoint puts the code back so the client's session
/// survives the outage. Putting a code back must not renew it: the 90 day window has to keep
/// running from the original creation time, or a caller could hold a code open indefinitely by
/// failing on purpose.
///
/// These tests pin the store-level invariant that makes the restore safe. They do not exercise the
/// HTTP call to Entra ID.
/// </summary>
public class RefreshCodeRestoreTests
{
    private const int TokenExpirationDays = 90;

    // The in-memory store keeps codes in a static dictionary, so every test uses its own code.
    private static string NewCode() => $"code-{Guid.NewGuid():N}";

    private static TokenData Data(string code, DateTime createdAt = default) => new()
    {
        Code = code,
        EntraRefreshToken = "entra-refresh-token",
        PkceState = new PkceStateData
        {
            ClientId = "client-id",
            RedirectUri = "https://localhost/callback",
            CodeChallenge = "challenge",
            CodeChallengeMethod = "S256",
            OriginalState = "state",
            Scope = "openid profile"
        },
        CreatedAt = createdAt
    };

    [Fact]
    public async Task Minting_a_code_without_a_creation_time_stamps_one()
    {
        var store = new InMemoryTokenStore();
        var code = NewCode();
        var before = DateTime.UtcNow;

        await store.StoreCodeData(Data(code));

        var stored = await store.GetAndConsumeCode(code);
        Assert.NotNull(stored);
        Assert.InRange(stored!.CreatedAt, before.AddSeconds(-1), DateTime.UtcNow.AddSeconds(1));
    }

    [Fact]
    public async Task Restoring_a_code_keeps_its_original_creation_time()
    {
        var store = new InMemoryTokenStore();
        var code = NewCode();
        var originallyCreatedAt = DateTime.UtcNow.AddDays(-30);

        await store.StoreCodeData(Data(code, originallyCreatedAt));

        // The token endpoint consumes the code, then Entra ID turns out to be unreachable.
        var consumed = await store.GetAndConsumeCode(code);
        Assert.NotNull(consumed);

        // The endpoint puts it back. This is the call the fix changes.
        await store.StoreCodeData(consumed!);

        var restored = await store.GetAndConsumeCode(code);
        Assert.NotNull(restored);
        Assert.Equal(originallyCreatedAt, restored!.CreatedAt);
    }

    [Fact]
    public async Task A_restored_code_still_expires_on_its_original_schedule()
    {
        var store = new InMemoryTokenStore();
        var code = NewCode();

        // One day short of the 90 day window.
        var originallyCreatedAt = DateTime.UtcNow.AddDays(-(TokenExpirationDays - 1));
        await store.StoreCodeData(Data(code, originallyCreatedAt));

        var consumed = await store.GetAndConsumeCode(code);
        Assert.NotNull(consumed);
        await store.StoreCodeData(consumed!);

        var restored = await store.GetAndConsumeCode(code);
        Assert.NotNull(restored);

        // Without the guard the restore resets CreatedAt to now, which buys another 90 days.
        // The code has to come back out of the store still one day from expiry.
        var remaining = restored!.CreatedAt.AddDays(TokenExpirationDays) - DateTime.UtcNow;
        Assert.True(
            remaining < TimeSpan.FromDays(2),
            $"restoring the code extended its life: {remaining.TotalDays:F1} days left, expected under 2");
    }

    [Fact]
    public async Task Repeated_restores_cannot_hold_a_code_open_past_its_window()
    {
        var store = new InMemoryTokenStore();
        var code = NewCode();

        // A caller that keeps failing on purpose, starting from a code that is nearly spent.
        var originallyCreatedAt = DateTime.UtcNow.AddDays(-(TokenExpirationDays - 1));
        await store.StoreCodeData(Data(code, originallyCreatedAt));

        for (var attempt = 0; attempt < 5; attempt++)
        {
            var consumed = await store.GetAndConsumeCode(code);
            Assert.NotNull(consumed);
            await store.StoreCodeData(consumed!);
        }

        var final = await store.GetAndConsumeCode(code);
        Assert.NotNull(final);
        Assert.Equal(originallyCreatedAt, final!.CreatedAt);
    }

    [Fact]
    public async Task An_expired_code_is_not_handed_back()
    {
        var store = new InMemoryTokenStore();
        var code = NewCode();

        await store.StoreCodeData(Data(code, DateTime.UtcNow.AddDays(-(TokenExpirationDays + 1))));

        Assert.Null(await store.GetAndConsumeCode(code));
    }

    [Fact]
    public async Task A_code_is_single_use_until_it_is_deliberately_restored()
    {
        var store = new InMemoryTokenStore();
        var code = NewCode();

        await store.StoreCodeData(Data(code, DateTime.UtcNow.AddDays(-1)));

        Assert.NotNull(await store.GetAndConsumeCode(code));
        Assert.Null(await store.GetAndConsumeCode(code));
    }
}
