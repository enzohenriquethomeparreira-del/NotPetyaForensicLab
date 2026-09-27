using Microsoft.Win32.SafeHandles;
using System.Security.Cryptography;
using System.Text.Json;

namespace HoneypotCrypto;

public sealed class ForensicVolume : IAsyncDisposable
{
    private readonly SafeFileHandle _handle;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly List<VirtualFileEntry> _entries = [];
    public ForensicVolumeHeader Header { get; private set; }
    public IReadOnlyList<VirtualFileEntry> Entries => _entries;
    internal SafeFileHandle Handle => _handle;

    private ForensicVolume(SafeFileHandle handle, ForensicVolumeHeader header) { _handle = handle; Header = header; }

    public static async Task<ForensicVolume> CreateAsync(SafeFileHandle handle, ForensicVolumeOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(handle);
        var directoryEnd = checked((long)ForensicVolumeLayout.HeaderSize + (long)options.MaximumFiles * ForensicVolumeLayout.DirectoryEntrySize);
        var dataOffset = ForensicVolumeLayout.Align(directoryEnd, options.BlockSize);
        var journalOffset = checked(options.VolumeSize - ForensicVolumeLayout.JournalSize - ForensicVolumeLayout.EscrowRegionSize);
        var escrowOffset = checked(options.VolumeSize - ForensicVolumeLayout.EscrowRegionSize);
        if (dataOffset >= journalOffset) throw new ArgumentOutOfRangeException(nameof(options), "Volume has no data region.");
        var header = new ForensicVolumeHeader(1, options.BlockSize, options.MaximumFiles, 0, ForensicVolumeLayout.HeaderSize,
            dataOffset, dataOffset, journalOffset, journalOffset, escrowOffset, options.VolumeSize);
        RandomAccess.SetLength(handle, options.VolumeSize);
        await WriteExactAsync(handle, header.Serialize(), 0, cancellationToken).ConfigureAwait(false);
        RandomAccess.FlushToDisk(handle);
        return new ForensicVolume(handle, header);
    }

    public static async Task<ForensicVolume> OpenAsync(SafeFileHandle handle, CancellationToken cancellationToken)
    {
        var headerBytes = new byte[ForensicVolumeLayout.HeaderSize];
        await ReadExactAsync(handle, headerBytes, 0, cancellationToken).ConfigureAwait(false);
        var header = ForensicVolumeHeader.Parse(headerBytes);
        if (RandomAccess.GetLength(handle) != header.VolumeSize) throw new InvalidDataException("Forensic-volume length does not match its header.");
        var volume = new ForensicVolume(handle, header);
        for (var index = 0; index < header.FileCount; index++)
        {
            var entryBytes = new byte[ForensicVolumeLayout.DirectoryEntrySize];
            await ReadExactAsync(handle, entryBytes, checked(header.DirectoryOffset + (long)index * entryBytes.Length), cancellationToken).ConfigureAwait(false);
            var entry = VirtualFileEntry.Parse(index, entryBytes);
            volume.ValidateEntryBounds(entry);
            volume._entries.Add(entry);
        }
        await volume.RecoverPendingAsync(cancellationToken).ConfigureAwait(false);
        return volume;
    }

    public async ValueTask<VirtualFileEntry> AddVirtualFileAsync(string logicalName, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(logicalName) || logicalName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) throw new ArgumentException("Invalid logical name.", nameof(logicalName));
        if (content.IsEmpty) throw new ArgumentException("Virtual files must not be empty.", nameof(content));
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_entries.Count >= Header.MaximumFiles) throw new InvalidOperationException("Virtual directory is full.");
            if (_entries.Any(e => string.Equals(e.LogicalName, logicalName, StringComparison.OrdinalIgnoreCase))) throw new InvalidOperationException("Duplicate logical name.");
            var allocated = checked((int)ForensicVolumeLayout.Align(content.Length, Header.BlockSize));
            var end = checked(Header.NextDataOffset + allocated);
            if (end > Header.DataEnd) throw new IOException("Forensic volume data region is full.");
            var padded = new byte[allocated];
            content.CopyTo(padded);
            await WriteExactAsync(_handle, padded, Header.NextDataOffset, cancellationToken).ConfigureAwait(false);
            var entry = new VirtualFileEntry(_entries.Count, Guid.NewGuid(), logicalName, Header.NextDataOffset, content.Length, allocated,
                SHA256.HashData(content.Span), false, [], [], []);
            await WriteEntryAsync(entry, cancellationToken).ConfigureAwait(false);
            _entries.Add(entry);
            Header = Header with { FileCount = _entries.Count, NextDataOffset = end };
            await WriteExactAsync(_handle, Header.Serialize(), 0, cancellationToken).ConfigureAwait(false);
            RandomAccess.FlushToDisk(_handle);
            CryptographicOperations.ZeroMemory(padded);
            return entry;
        }
        finally { _gate.Release(); }
    }

    public async ValueTask<byte[]> ReadVirtualFileAsync(VirtualFileEntry entry, CancellationToken cancellationToken)
    {
        ValidateEntryBounds(entry);
        var content = new byte[entry.PlaintextLength];
        await ReadExactAsync(_handle, content, entry.DataOffset, cancellationToken).ConfigureAwait(false);
        return content;
    }

    internal async ValueTask WriteEntryAsync(VirtualFileEntry entry, CancellationToken cancellationToken)
    {
        if (entry.Index < 0 || entry.Index >= Header.MaximumFiles) throw new ArgumentOutOfRangeException(nameof(entry));
        var offset = checked(Header.DirectoryOffset + (long)entry.Index * ForensicVolumeLayout.DirectoryEntrySize);
        await WriteExactAsync(_handle, entry.Serialize(), offset, cancellationToken).ConfigureAwait(false);
        if (entry.Index < _entries.Count) _entries[entry.Index] = entry;
    }

    internal async ValueTask WriteDataAsync(VirtualFileEntry entry, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        ValidateEntryBounds(entry);
        if (data.Length != entry.PlaintextLength) throw new ArgumentException("In-place writes must preserve logical length.", nameof(data));
        await WriteExactAsync(_handle, data, entry.DataOffset, cancellationToken).ConfigureAwait(false);
    }

    internal async ValueTask WriteJournalAsync(ReadOnlyMemory<byte> record, CancellationToken cancellationToken)
    {
        if (record.Length > ForensicVolumeLayout.JournalSize) throw new ArgumentOutOfRangeException(nameof(record));
        var buffer = new byte[ForensicVolumeLayout.JournalSize];
        record.CopyTo(buffer);
        await WriteExactAsync(_handle, buffer, Header.JournalOffset, cancellationToken).ConfigureAwait(false);
        RandomAccess.FlushToDisk(_handle);
    }

    internal void Flush() => RandomAccess.FlushToDisk(_handle);

    internal async ValueTask BeginTransactionAsync(VirtualFileEntry oldEntry, ReadOnlyMemory<byte> currentData, string operation, CancellationToken cancellationToken)
    {
        if (currentData.Length != oldEntry.PlaintextLength || currentData.Length > ForensicVolumeLayout.EscrowRegionSize)
            throw new InvalidOperationException("Virtual file exceeds the bounded recovery staging region.");
        var staging = new byte[ForensicVolumeLayout.EscrowRegionSize];
        currentData.CopyTo(staging);
        await WriteExactAsync(_handle, staging, Header.EscrowOffset, cancellationToken).ConfigureAwait(false);
        RandomAccess.FlushToDisk(_handle);
        var journal = new VolumeJournal("forensic-volume-journal-v2", "Prepared", operation, oldEntry.Index, Convert.ToBase64String(oldEntry.Serialize()), currentData.Length,
            Convert.ToHexString(SHA256.HashData(currentData.Span)));
        await WriteJournalAsync(journal.Serialize(), cancellationToken).ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(staging);
    }

    internal async ValueTask AdvanceTransactionAsync(string stage, CancellationToken cancellationToken)
    {
        var journal = await ReadJournalAsync(cancellationToken).ConfigureAwait(false) ?? throw new InvalidDataException("Transaction journal is missing.");
        await WriteJournalAsync((journal with { Stage = stage }).Serialize(), cancellationToken).ConfigureAwait(false);
    }

    internal async ValueTask CompleteTransactionAsync(CancellationToken cancellationToken)
    {
        await AdvanceTransactionAsync("Committed", cancellationToken).ConfigureAwait(false);
        await ClearStagingAsync(cancellationToken).ConfigureAwait(false);
        await ClearJournalAsync(cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<bool> RecoverPendingAsync(CancellationToken cancellationToken)
    {
        VolumeJournal? journal;
        try { journal = await ReadJournalAsync(cancellationToken).ConfigureAwait(false); }
        catch (JsonException)
        {
            await ClearJournalAsync(cancellationToken).ConfigureAwait(false);
            return false;
        }
        if (journal is null) return false;
        if (journal.Stage == "Committed")
        {
            await ClearStagingAsync(cancellationToken).ConfigureAwait(false);
            await ClearJournalAsync(cancellationToken).ConfigureAwait(false);
            return false;
        }
        var oldEntryBytes = Convert.FromBase64String(journal.OldEntry);
        var oldEntry = VirtualFileEntry.Parse(journal.EntryIndex, oldEntryBytes);
        var staged = new byte[journal.StagedLength];
        await ReadExactAsync(_handle, staged, Header.EscrowOffset, cancellationToken).ConfigureAwait(false);
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(staged), Convert.FromHexString(journal.StagedSha256)))
            throw new InvalidDataException("Recovery staging hash mismatch.");
        await WriteDataAsync(oldEntry, staged, cancellationToken).ConfigureAwait(false);
        await WriteEntryAsync(oldEntry, cancellationToken).ConfigureAwait(false);
        RandomAccess.FlushToDisk(_handle);
        await ClearStagingAsync(cancellationToken).ConfigureAwait(false);
        await ClearJournalAsync(cancellationToken).ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(staged);
        return true;
    }

    private async ValueTask<VolumeJournal?> ReadJournalAsync(CancellationToken cancellationToken)
    {
        var buffer = new byte[ForensicVolumeLayout.JournalSize];
        await ReadExactAsync(_handle, buffer, Header.JournalOffset, cancellationToken).ConfigureAwait(false);
        var length = Array.IndexOf(buffer, (byte)0);
        if (length == 0) return null;
        if (length < 0) length = buffer.Length;
        return VolumeJournal.Parse(buffer.AsSpan(0, length));
    }

    private async ValueTask ClearJournalAsync(CancellationToken cancellationToken)
    {
        await WriteExactAsync(_handle, new byte[ForensicVolumeLayout.JournalSize], Header.JournalOffset, cancellationToken).ConfigureAwait(false);
        RandomAccess.FlushToDisk(_handle);
    }

    private async ValueTask ClearStagingAsync(CancellationToken cancellationToken)
    {
        await WriteExactAsync(_handle, new byte[ForensicVolumeLayout.EscrowRegionSize], Header.EscrowOffset, cancellationToken).ConfigureAwait(false);
        RandomAccess.FlushToDisk(_handle);
    }

    private void ValidateEntryBounds(VirtualFileEntry entry)
    {
        var end = checked(entry.DataOffset + entry.AllocatedLength);
        if (entry.DataOffset < Header.DataOffset || end > Header.DataEnd || entry.PlaintextLength <= 0 || entry.PlaintextLength > entry.AllocatedLength)
            throw new InvalidDataException("Virtual file entry escapes the data region.");
    }

    internal static async ValueTask WriteExactAsync(SafeFileHandle handle, ReadOnlyMemory<byte> data, long offset, CancellationToken cancellationToken) =>
        await RandomAccess.WriteAsync(handle, data, offset, cancellationToken).ConfigureAwait(false);

    internal static async ValueTask ReadExactAsync(SafeFileHandle handle, Memory<byte> data, long offset, CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < data.Length)
        {
            var read = await RandomAccess.ReadAsync(handle, data[total..], checked(offset + total), cancellationToken).ConfigureAwait(false);
            if (read == 0) throw new EndOfStreamException("Unexpected end of forensic volume.");
            total += read;
        }
    }

    public ValueTask DisposeAsync()
    {
        _gate.Dispose();
        _handle.Dispose();
        return ValueTask.CompletedTask;
    }
}
