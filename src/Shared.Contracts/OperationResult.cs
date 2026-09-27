namespace Shared.Contracts;

public sealed record OperationResult(bool Success, string Code, string Message, IReadOnlyDictionary<string, string>? Artifacts = null)
{
    public static OperationResult Ok(string message, IReadOnlyDictionary<string, string>? artifacts = null) => new(true, "OK", message, artifacts);
    public static OperationResult Fail(string code, string message) => new(false, code, message);
}
