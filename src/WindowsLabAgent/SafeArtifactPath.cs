using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Text;

namespace WindowsLabAgent;

public static class SafeArtifactPath
{
    public const string RootMarkerName = ".forensic-lab-root";
    private static readonly HashSet<string> AllowedExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".img", ".pcapng", ".json", ".jsonl", ".csv", ".etl", ".evtx", ".bin" };

    public static string ValidateLexically(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path)) throw new ArgumentException("Artifact path must be absolute.", nameof(path));
        if (path.StartsWith(@"\\", StringComparison.Ordinal) || path.StartsWith(@"\\?\", StringComparison.Ordinal) || path.StartsWith(@"\\.\", StringComparison.Ordinal))
            throw new ArgumentException("UNC and Windows device paths are forbidden.", nameof(path));
        if (path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(segment => segment == ".."))
            throw new ArgumentException("Path traversal segments are forbidden.", nameof(path));
        var full = Path.GetFullPath(path);
        if (Path.EndsInDirectorySeparator(full)) throw new ArgumentException("Artifact path must name a file.", nameof(path));
        if (!AllowedExtensions.Contains(Path.GetExtension(full))) throw new ArgumentException("Artifact extension is not permitted.", nameof(path));
        return full;
    }

    public static string ValidateForLab(string path)
    {
        var full = ValidateLexically(path);
        var parent = Directory.GetParent(full)?.FullName ?? throw new ArgumentException("Artifact has no parent directory.", nameof(path));
        EnsureNoReparseAncestors(parent);
        var markerRoot = FindMarkerRoot(parent) ?? throw new UnauthorizedAccessException($"No {RootMarkerName} marker found in artifact ancestry.");
        var relative = Path.GetRelativePath(markerRoot, full);
        if (relative == ".." || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Artifact escapes the marked laboratory root.");
        if (OperatingSystem.IsWindows())
        {
            var drive = new DriveInfo(Path.GetPathRoot(full)!);
            if (drive.DriveType != DriveType.Fixed) throw new UnauthorizedAccessException("Only fixed local drives are permitted.");
            var processPath = Environment.ProcessPath ?? throw new InvalidOperationException("Unable to resolve the agent executable path.");
            var volumeProbe = File.Exists(full) ? full : parent;
            if (!string.Equals(GetVolumeIdentity(volumeProbe), GetVolumeIdentity(processPath), StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Artifacts must remain on the agent system volume; secondary mounted volumes are forbidden.");
        }
        return full;
    }

    public static SafeFileHandle OpenPreparedOutputFile(string manifestPath, long maximumLength, bool requireEmpty = true)
    {
        if (maximumLength <= 0 || maximumLength > ManifestValidator.MaximumVolumeCeiling) throw new ArgumentOutOfRangeException(nameof(maximumLength));
        var full = ValidateForLab(manifestPath);
        if (!File.Exists(full)) throw new FileNotFoundException("Output artifacts must be precreated inside the marked laboratory root.", full);
        var handle = File.OpenHandle(full, FileMode.Open, FileAccess.ReadWrite, FileShare.None, FileOptions.Asynchronous | FileOptions.WriteThrough);
        try
        {
            RevalidateHandle(handle, full);
            var length = RandomAccess.GetLength(handle);
            if (length > maximumLength) throw new InvalidDataException("Prepared artifact exceeds its signed maximum length.");
            if (requireEmpty && length != 0) throw new InvalidDataException("Prepared output artifact must be empty.");
            return handle;
        }
        catch { handle.Dispose(); throw; }
    }

    public static SafeFileHandle OpenExistingRegularFile(string manifestPath, FileAccess access)
    {
        var full = ValidateForLab(manifestPath);
        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Reparse-point artifacts are forbidden.");
        var handle = File.OpenHandle(full, FileMode.Open, access, FileShare.Read, FileOptions.Asynchronous | FileOptions.WriteThrough);
        try { RevalidateHandle(handle, full); return handle; }
        catch { handle.Dispose(); throw; }
    }

    private static void RevalidateHandle(SafeFileHandle handle, string expectedPath)
    {
        if (!OperatingSystem.IsWindows()) return;
        var buffer = new StringBuilder(1024);
        var length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
        if (length == 0 || length >= (uint)buffer.Capacity) throw new IOException("Unable to resolve final artifact path.");
        var final = buffer.ToString();
        if (final.StartsWith(@"\\?\", StringComparison.Ordinal)) final = final[4..];
        if (!string.Equals(Path.GetFullPath(final), expectedPath, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Artifact path changed during acquisition.");
        EnsureNoReparseAncestors(Path.GetDirectoryName(expectedPath)!);
        if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfoClass, out var tagInfo, (uint)Marshal.SizeOf<FileAttributeTagInfo>()))
            throw new IOException("Unable to query artifact attributes from its handle.", new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
        var attributes = (FileAttributes)tagInfo.FileAttributes;
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 || tagInfo.ReparseTag != 0)
            throw new UnauthorizedAccessException("Artifact is not a regular file.");
    }

    private static string? FindMarkerRoot(string start)
    {
        for (var current = new DirectoryInfo(start); current is not null; current = current.Parent)
            if (File.Exists(Path.Combine(current.FullName, RootMarkerName)) &&
                string.Equals(File.ReadAllText(Path.Combine(current.FullName, RootMarkerName)), "FORENSIC-LAB-V1", StringComparison.Ordinal)) return current.FullName;
        return null;
    }

    private static void EnsureNoReparseAncestors(string start)
    {
        for (var current = new DirectoryInfo(start); current is not null; current = current.Parent)
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException("Reparse-point ancestors are forbidden.");
    }

    private static string GetVolumeIdentity(string path)
    {
        var mountPoint = new StringBuilder(1024);
        if (!GetVolumePathName(path, mountPoint, (uint)mountPoint.Capacity)) throw new IOException("Unable to resolve volume mount point.");
        var volumeName = new StringBuilder(1024);
        if (!GetVolumeNameForVolumeMountPoint(mountPoint.ToString(), volumeName, (uint)volumeName.Capacity)) throw new IOException("Unable to resolve volume identity.");
        return volumeName.ToString();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo { public uint FileAttributes; public uint ReparseTag; }

    private const int FileAttributeTagInfoClass = 9;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle hFile, StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle hFile, int fileInformationClass, out FileAttributeTagInfo fileInformation, uint bufferSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumePathName(string fileName, StringBuilder volumePathName, uint bufferLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeNameForVolumeMountPoint(string volumeMountPoint, StringBuilder volumeName, uint bufferLength);
}
