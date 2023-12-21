using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

// ReSharper disable MemberCanBePrivate.Global

namespace WinTun;

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

    protected override bool ReleaseHandle()
    {
        Native.CloseAdapter(handle);
        return true;
    }

    public override bool IsInvalid => false;

    /// <summary>
    /// Returns the LUID of the adapter.
    /// </summary>
    /// <returns> Adapter LUID </returns>
    public (ulong, ulong) GetLuid()
    {
        unsafe
        {
            var mem = stackalloc ulong[2];
            Native.GetAdapterLUID(handle, (nint)mem);
            return (mem[0], mem[1]);
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
        if (capacity is < MinRingCapacity or > MaxRingCapacity || (capacity & (capacity - 1)) == 0) 
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

public class Session : CriticalHandle
{
    public const int MaxIpPacketSize = 0xFFFF;

    internal Session(nint handle) : base(handle)
    {
    }

    protected override bool ReleaseHandle()
    {
        Native.EndSession(handle);
        return true;
    }

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
    
    /// <summary>
    /// Wait until more packets are ready for read
    /// </summary>
    /// <param name="timeout"> Timeout for wait </param>
    /// <returns> true if wait completed, false if wait timed-out </returns>
    /// <exception cref="Win32Exception"></exception>
    public bool WaitForRead(TimeSpan timeout) =>
        Native.WaitForSingleObject(Native.GetReadWaitEvent(handle), (uint)timeout.Milliseconds) switch
        {
            0 => true,
            0x102 => false,
            _ => throw new Win32Exception(Marshal.GetLastWin32Error())
        };

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