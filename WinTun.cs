using System.Runtime.InteropServices;
using System.ComponentModel;

// ReSharper disable MemberCanBePrivate.Global
namespace WinTun;

using AdapterHandle = nint;
using SessionHandle = nint;

/// <summary> Log level enumeration </summary>
public enum LoggerLevel
{
    /// <summary> INFO level logger </summary>
    Info = 0,
    /// <summary> WARN level logger </summary>
    Warn = 1,
    /// <summary> ERROR level logger </summary>
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
}

public static class Logger
{
    /// <summary>
    /// Called by internal logger to report diagnostic messages
    /// @param level         Message level.
    /// @param timestamp     Message timestamp in in 100ns intervals since 1601-01-01 UTC.
    /// @param message       Message text.
    /// </summary>
    public delegate void Callback(LoggerLevel level, ulong timestamp, string message);

    private static Callback _gLogger = (_, _, _) => { };
    private static int _gDrvSet;

    public static void SetCallback(Callback callback)
    {
        Volatile.Write(ref _gLogger, callback);
        if (Interlocked.Exchange(ref _gDrvSet, 1) == 0)
        {
            // This leaks the function object permanently, which is the reason for the mux 
            Native.SetLogger(CallbackMux);
        }
    }

    private static void CallbackMux(LoggerLevel level, ulong timestamp, string message) =>
        _gLogger(level, timestamp, message);
}

/// <summary> WinTun driver level operations </summary>
public static class Driver
{
    /// <summary>
    /// Determines the version of the Wintun driver currently loaded.
    /// </summary>
    /// <returns> The version number </returns>
    /// <exception cref="Win32Exception"> ERROR_FILE_NOT_FOUND Wintun not loaded </exception>
    public static uint GetRunningVersion()
    {
        var res = Native.GetRunningDriverVersion();
        if (res == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
        return res;
    }

    /// <summary>
    /// Deletes the Wintun driver if there are no more adapters in use.
    /// </summary>
    /// <exception cref="Win32Exception"></exception>
    public static void DeleteDriver()
    {
        if (!Native.DeleteDriver()) throw new Win32Exception(Marshal.GetLastWin32Error());
    }
}

/// <summary> WinTun Adapter Instance </summary>
public class Adapter : CriticalHandle
{
    private Adapter(nint handle) : base(handle)
    {
    }

    /// <summary>
    /// Opens an existing Wintun adapter.
    /// </summary>
    /// <param name="name"> The requested name of the adapter, 127 chars maximum </param>
    /// <exception cref="ArgumentException"> name too long </exception>
    /// <exception cref="Win32Exception"></exception>
    public static Adapter Open(string name)
    {
        if (name.Length > 127) throw new ArgumentException("too long", nameof(name)); 
        var hdc = Native.OpenAdapter(name);
        if (hdc == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
        return new Adapter(hdc);
    }

    /// <summary>
    /// Creates a new Wintun adapter.
    /// </summary>
    /// <param name="name"> The requested name of the adapter, 127 chars maximum </param>
    /// <param name="tunnelType"> Name of the adapter tunnel type, 127 chars maximum </param>
    /// <param name="requestedGuid">
    /// The GUID of the created network adapter, which then influences NLA generation deterministically.
    /// It is called "requested" GUID because the API it uses is completely undocumented,
    /// and so there could be minor interesting complications with its usage.
    /// </param>
    /// <returns></returns>
    /// <exception cref="ArgumentException"> name or tunnelType too long </exception>
    /// <exception cref="Win32Exception"></exception>
    public static Adapter Create(string name, string tunnelType, in Guid requestedGuid)
    {
        if (name.Length > 127) throw new ArgumentException("too long", nameof(name)); 
        if (tunnelType.Length > 127) throw new ArgumentException("too long", nameof(tunnelType)); 
        var hdc = Native.CreateAdapter(name, tunnelType, requestedGuid);
        if (hdc == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
        return new Adapter(hdc);
    }

    /// <inheritdoc/>
    protected override bool ReleaseHandle()
    {
        Native.CloseAdapter(handle);
        return true;
    }

    /// <inheritdoc/>
    public override bool IsInvalid => false;

    /// <summary>
    /// Returns the LUID of the adapter.
    /// </summary>
    /// <returns> Adapter LUID </returns>
    public ulong GetLuid()
    {
        unsafe
        {
            var mem = stackalloc ulong[1];
            Native.GetAdapterLUID(handle, (nint)mem);
            return mem[0];
        }
    }

    /// Minimum ring capacity, 128KiB.
    public const int MinRingCapacity = 0x20000;


    /// Maximum ring capacity, 64MiB.
    public const int MaxRingCapacity = 0x4000000;

    /// <summary>
    /// Starts Wintun session.
    /// </summary>
    /// <param name="capacity"> Rings capacity. Must be in [MinRingCapacity, MaxRingCapacity] and a power of two. </param>
    /// <returns> Wintun session </returns>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="Win32Exception"></exception>
    public Session StartSession(uint capacity)
    {
        if (capacity is < MinRingCapacity or > MaxRingCapacity || (capacity & (capacity - 1)) != 0) 
            throw new ArgumentException("", nameof(capacity));
        var hdc = Native.StartSession(handle, capacity);
        if (hdc == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
        return new Session(hdc);
    }
}

public readonly struct Packet
{
    internal readonly nint Data;
    private readonly uint _size;

    internal Packet(nint data, uint size)
    {
        Data = data;
        _size = size;
    }

    public Span<byte> Span
    {
        get
        {
            unsafe
            {
                return new Span<byte>((void*)Data, (int)_size);
            }
        }
    }
}

/// <summary> WinTun Session Instance </summary>
public class Session : CriticalHandle
{
    public const int MaxIpPacketSize = 0xFFFF;

    internal Session(nint handle) : base(handle)
    {
    }

    /// <inheritdoc/>
    protected override bool ReleaseHandle()
    {
        Native.EndSession(handle);
        return true;
    }

    /// <inheritdoc/>
    public override bool IsInvalid => false;

    /// <summary>
    /// Retrieves one or packet.
    /// After the packet content is consumed, call ReleaseReceivePacket with Packet returned from this function to release internal buffer.
    /// This function is thread-safe.
    /// </summary>
    /// <param name="packet"> Layer 3 IPv4 or IPv6 packet. Client may modify its content at will </param>
    /// <returns> true if allocation succeeds, false if Wintun buffer is exhausted </returns>
    /// <exception cref="Win32Exception">
    /// <br/>ERROR_HANDLE_EOF     Wintun adapter is terminating;
    /// <br/>ERROR_INVALID_DATA   Wintun buffer is corrupt
    /// </exception>
    public bool ReceivePacket(out Packet packet)
    {
        var res = Native.ReceivePacket(handle, out var pSize);
        if (res == 0)
        {
            var err = Marshal.GetLastWin32Error();
            if (err != 259) throw new Win32Exception(err);
            packet = default;
            return false;
        }

        packet = new Packet(res, pSize);
        return true;
    }

    /// <summary>
    /// Releases internal buffer after the received packet has been processed by the client.
    /// This function is thread-safe.
    /// </summary>
    /// <param name="packet"> Packet obtained with ReceivePacket </param>
    public void ReleaseReceivePacket(Packet packet) => Native.ReleaseReceivePacket(handle, packet.Data);
    
    /// <summary> Gets Wintun session's read-wait event handle. </summary>
    /// <returns>
    /// Pointer to receive event handle to wait for available data when reading. <br/>
    /// Should ReceivePackets return false (after spinning on it for a while under heavy load),
    /// wait for this event to become signaled before retrying ReceivePackets. <br/>
    /// Do not call CloseHandle on this event - it is managed by the session.
    /// </returns>
    public nint GetReadWaitEvent() => Native.GetReadWaitEvent(handle);

    /// <summary>
    /// Allocates memory for a packet to send.
    /// After the memory is filled with packet data, call SendPacket to send and release internal buffer.
    /// AllocateSendPacket is thread-safe and the AllocateSendPacket order of calls define the packet sending order.
    /// </summary>
    /// <param name="size"> Exact packet size. Must be less or equal to MaxIpPacketSize </param>
    /// <param name="packet"> Allocated packet to prepare layer 3 IPv4 or IPv6 packet for sending </param>
    /// <returns> true if allocation succeeds, false if Wintun buffer is full </returns>
    /// <exception cref="ArgumentException"> size too large </exception>
    /// <exception cref="Win32Exception">
    /// <br/>ERROR_HANDLE_EOF       Wintun adapter is terminating
    /// <br/>ERROR_BUFFER_OVERFLOW  Wintun buffer is full;
    /// </exception>
    public bool AllocateSendPacket(uint size, out Packet packet)
    {
        if (size > MaxIpPacketSize) throw new ArgumentException("too large", nameof(size));
        var res = Native.AllocateSendPacket(handle, size);
        if (res == 0)
        {
            var err = Marshal.GetLastWin32Error();
            if (err != 111) throw new Win32Exception(err);
            packet = default;
            return false;
        }

        packet = new Packet(res, size);
        return true;
    }

    /// <summary>
    /// Sends the packet and releases internal buffer. WintunSendPacket is thread-safe,
    /// but the AllocateSendPacket order of calls define the packet sending order.
    /// This means the packet is not guaranteed to be sent in the SendPacket yet.
    /// </summary>
    /// <param name="packet">Packet obtained with AllocateSendPacket</param>
    public void SendPacket(Packet packet) => Native.SendPacket(handle, packet.Data);
}