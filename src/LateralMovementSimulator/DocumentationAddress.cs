namespace LateralMovementSimulator;

public readonly record struct DocumentationAddress(byte A, byte B, byte C, byte D)
{
    public static DocumentationAddress Parse(string value)
    {
        var parts = value.Split('.', StringSplitOptions.TrimEntries);
        if (parts.Length != 4 || !parts.All(p => byte.TryParse(p, out _))) throw new ArgumentException("Invalid IPv4 address.", nameof(value));
        var bytes = parts.Select(p => byte.Parse(p, System.Globalization.CultureInfo.InvariantCulture)).ToArray();
        var allowed = bytes is [192, 0, 2, _] or [198, 51, 100, _] or [203, 0, 113, _];
        if (!allowed) throw new ArgumentException("Only RFC 5737 documentation addresses are permitted.", nameof(value));
        return new DocumentationAddress(bytes[0], bytes[1], bytes[2], bytes[3]);
    }

    public byte[] ToBytes() => [A, B, C, D];
    public override string ToString() => $"{A}.{B}.{C}.{D}";
}
