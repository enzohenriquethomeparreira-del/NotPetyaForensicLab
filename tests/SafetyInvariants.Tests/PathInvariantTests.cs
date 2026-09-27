using WindowsLabAgent;

namespace SafetyInvariants.Tests;

public sealed class PathInvariantTests
{
    [Theory]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData(@"\\.\Harddisk0")]
    [InlineData(@"\\?\Volume{00000000-0000-0000-0000-000000000000}")]
    [InlineData(@"\\server\share\x.img")]
    [InlineData(@"relative.img")]
    public void Device_unc_and_relative_paths_are_rejected(string path) =>
        Assert.ThrowsAny<Exception>(() => SafeArtifactPath.ValidateLexically(path));

    [Fact]
    public void Allowed_file_must_be_beneath_marked_root()
    {
        var root = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, SafeArtifactPath.RootMarkerName), "FORENSIC-LAB-V1");
        try { Assert.StartsWith(root, SafeArtifactPath.ValidateForLab(Path.Combine(root, "a.img"))); }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public void Output_file_must_be_precreated_and_empty()
    {
        var root = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, SafeArtifactPath.RootMarkerName), "FORENSIC-LAB-V1");
        var output = Path.Combine(root, "artifact.img");
        Assert.Throws<FileNotFoundException>(() => SafeArtifactPath.OpenPreparedOutputFile(output, 1024));
        File.WriteAllText(output, "not-empty");
        Assert.Throws<InvalidDataException>(() => SafeArtifactPath.OpenPreparedOutputFile(output, 1024));
        Directory.Delete(root, true);
    }
}
