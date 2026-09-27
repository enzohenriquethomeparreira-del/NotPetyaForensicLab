using System.Text.Json;
using System.Text.Json.Serialization;

namespace Shared.Contracts;

public static class ContractJson
{
    public static JsonSerializerOptions CreateOptions() => new(JsonSerializerDefaults.General)
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false) }
    };
}
