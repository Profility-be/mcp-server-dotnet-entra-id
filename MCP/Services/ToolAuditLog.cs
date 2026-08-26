using System.Diagnostics;
using System.Security.Claims;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace MCP.Services;

/// <summary>
/// Audit trail for MCP tool invocations. A call-tool filter is the one place every tool call passes
/// through, so cross-cutting concerns belong here rather than repeated in each tool.
/// </summary>
public static class ToolAuditLog
{
    private const string LoggerCategory = "MCP.ToolAudit";

    /// <summary>
    /// Records who called which tool, whether it succeeded, and how long it took.
    /// </summary>
    /// <remarks>
    /// Argument <b>values</b> are deliberately never logged - a tool argument can contain anything a
    /// caller types, and an audit log is exactly the wrong place for it to end up. Only the argument
    /// names are recorded, which is enough to reconstruct what was called without retaining content.
    /// Same reasoning as the claim allowlist in WhoAmITool.
    /// </remarks>
    public static McpRequestFilter<CallToolRequestParams, CallToolResult> Filter =>
        next => async (context, cancellationToken) =>
        {
            var logger = context.Services?.GetService(typeof(ILoggerFactory)) is ILoggerFactory factory
                ? factory.CreateLogger(LoggerCategory)
                : null;

            var toolName = context.Params?.Name ?? "(unknown)";
            var caller = Describe(context.User);
            var argumentNames = context.Params?.Arguments is { Count: > 0 } arguments
                ? string.Join(", ", arguments.Select(argument => argument.Key))
                : "(none)";

            var startTimestamp = Stopwatch.GetTimestamp();
            try
            {
                var result = await next(context, cancellationToken);
                var elapsed = Stopwatch.GetElapsedTime(startTimestamp);

                // A tool that fails gracefully returns a result with IsError set rather than throwing,
                // so both outcomes have to be inspected to get an honest audit trail.
                if (result.IsError == true)
                {
                    logger?.LogWarning(
                        "Tool {Tool} returned an error for {Caller} in {ElapsedMs}ms (args: {ArgumentNames})",
                        toolName, caller, (long)elapsed.TotalMilliseconds, argumentNames);
                }
                else
                {
                    logger?.LogInformation(
                        "Tool {Tool} succeeded for {Caller} in {ElapsedMs}ms (args: {ArgumentNames})",
                        toolName, caller, (long)elapsed.TotalMilliseconds, argumentNames);
                }

                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                var elapsed = Stopwatch.GetElapsedTime(startTimestamp);
                logger?.LogInformation(
                    "Tool {Tool} was cancelled for {Caller} after {ElapsedMs}ms",
                    toolName, caller, (long)elapsed.TotalMilliseconds);
                throw;
            }
            catch (Exception ex)
            {
                var elapsed = Stopwatch.GetElapsedTime(startTimestamp);
                logger?.LogError(ex,
                    "Tool {Tool} threw for {Caller} after {ElapsedMs}ms (args: {ArgumentNames})",
                    toolName, caller, (long)elapsed.TotalMilliseconds, argumentNames);
                throw;
            }
        };

    /// <summary>
    /// Identifies the caller for the audit record: the Entra ID object id, which is stable and does
    /// not change when someone is renamed, plus the UPN to keep the log readable.
    /// </summary>
    private static string Describe(ClaimsPrincipal? user)
    {
        if (user?.Identity?.IsAuthenticated != true)
        {
            return "anonymous";
        }

        var objectId = user.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value
                       ?? user.FindFirst("oid")?.Value
                       ?? user.FindFirst(ClaimTypes.NameIdentifier)?.Value
                       ?? "unknown-oid";

        var upn = user.FindFirst(ClaimTypes.Upn)?.Value
                  ?? user.FindFirst("upn")?.Value
                  ?? user.FindFirst("preferred_username")?.Value;

        return upn is null ? objectId : $"{objectId} ({upn})";
    }
}
