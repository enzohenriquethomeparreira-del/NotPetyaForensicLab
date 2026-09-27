namespace Shared.Contracts;

public sealed record ValidationResult(bool IsValid, string Code, string Message)
{
    public static ValidationResult Valid() => new(true, "OK", "Valid");
    public static ValidationResult Invalid(string code, string message) => new(false, code, message);
}
