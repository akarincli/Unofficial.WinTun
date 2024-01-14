using System.Runtime.InteropServices;

namespace WinTun;

using AdapterHandle = nint;
using SessionHandle = nint;

public enum LoggerLevel
{
    Info = 0,
    Warn = 1,
    Error = 2
}

internal static partial class Native
{
    private const string DyName = "wintun";

    [LibraryImport(DyName, EntryPoint = "WintunCreateAdapter", SetLastError = true,
        StringMarshalling = StringMarshalling.Utf16)]
    internal static partial AdapterHandle CreateAdapter(string name, string tunnelType, in Guid requestedGuid);

    [LibraryImport(DyName, EntryPoint = "WintunOpenAdapter", SetLastError = true,
        StringMarshalling = StringMarshalling.Utf16)]
    internal static partial AdapterHandle OpenAdapter(string name);

    [LibraryImport(DyName, EntryPoint = "WintunCloseAdapter")]
    internal static partial void CloseAdapter(AdapterHandle adapter);

    [LibraryImport(DyName, EntryPoint = "WintunDeleteDriver", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool DeleteDriver();

    [LibraryImport(DyName, EntryPoint = "WintunGetAdapterLUID")]
    internal static partial void GetAdapterLUID(AdapterHandle adapter, nint luid);

    [LibraryImport(DyName, EntryPoint = "WintunGetRunningDriverVersion")]
    internal static partial uint GetRunningDriverVersion();

    public delegate void LoggerCallback(
        [MarshalAs(UnmanagedType.I4)] LoggerLevel level, ulong timestamp,
        [MarshalAs(UnmanagedType.LPWStr)] string message
    );

    [LibraryImport(DyName, EntryPoint = "WintunSetLogger")]
    internal static partial void SetLogger([MarshalAs(UnmanagedType.FunctionPtr)] LoggerCallback newLogger);

    [LibraryImport(DyName, EntryPoint = "WintunStartSession", SetLastError = true)]
    internal static partial SessionHandle StartSession(AdapterHandle adapter, uint capacity);

    [LibraryImport(DyName, EntryPoint = "WintunEndSession")]
    internal static partial void EndSession(SessionHandle session);

    /**
     * Gets Wintun session's read-wait event handle.
     *
     * @param session       Wintun session handle obtained with WintunStartSession
     *
     * @return Pointer to receive event handle to wait for available data when reading. Should
     *         WintunReceivePackets return ERROR_NO_MORE_ITEMS (after spinning on it for a while under heavy
     *         load), wait for this event to become signaled before retrying WintunReceivePackets. Do not call
     *         CloseHandle on this event - it is managed by the session.
     */
    [LibraryImport(DyName, EntryPoint = "WintunGetReadWaitEvent")]
    internal static partial nint GetReadWaitEvent(SessionHandle session);

    [LibraryImport(DyName, EntryPoint = "WintunReceivePacket", SetLastError = true)]
    internal static partial nint ReceivePacket(SessionHandle session, out uint packetSize);

    [LibraryImport(DyName, EntryPoint = "WintunReleaseReceivePacket")]
    internal static partial void ReleaseReceivePacket(SessionHandle session, nint packet);

    [LibraryImport(DyName, EntryPoint = "WintunAllocateSendPacket", SetLastError = true)]
    internal static partial nint AllocateSendPacket(SessionHandle session, uint packetSize);

    [LibraryImport(DyName, EntryPoint = "WintunSendPacket")]
    internal static partial void SendPacket(SessionHandle session, nint packet);
    
    [LibraryImport("kernel32.dll", SetLastError =true)]
    internal static partial uint WaitForSingleObject(nint hHandle, uint dwMilliseconds);
}