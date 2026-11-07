using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace LightweightCustomProtocol.Client
{
    public class LcpClientOptions
    {
        public string ServerHost { get; set; } = "platform.potatolight.cn";
        public int PortStrict { get; set; } = LcpConstants.DefaultPortStrict;
        public int PortDisaster { get; set; } = LcpConstants.DefaultPortDisaster;
        public HashSet<string> PinnedSpkiHashes { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public TimeSpan IPv6RaceWindow { get; set; } = TimeSpan.FromMilliseconds(1000);
        public string? StaticFallbackIPv4 { get; set; } = "49.232.234.137";
        public bool InsecureSkipCA { get; set; } = false;
    }

    public class LcpClient : IAsyncDisposable
    {
        private readonly LcpClientOptions _options;
        private QuicConnection? _connection;
        private readonly SemaphoreSlim _lock = new(1, 1);

        public LcpClient(LcpClientOptions options)
        {
            _options = options;
        }

        public async ValueTask<QuicConnection> ConnectAsync(CancellationToken cancellationToken = default)
        {
            await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_connection != null)
                {
                    return _connection;
                }

                _connection = await DialMultiTierAsync(cancellationToken).ConfigureAwait(false);
                return _connection;
            }
            finally
            {
                _lock.Release();
            }
        }

        private async Task<QuicConnection> DialMultiTierAsync(CancellationToken cancellationToken)
        {
            var (v6Addrs, v4Addrs) = await ResolveAddressesAsync(_options.ServerHost, cancellationToken).ConfigureAwait(false);
            if (v4Addrs.Count == 0 && !string.IsNullOrWhiteSpace(_options.StaticFallbackIPv4))
            {
                if (IPAddress.TryParse(_options.StaticFallbackIPv4, out var fallbackIp))
                {
                    v4Addrs.Add(fallbackIp);
                }
            }

            bool hasV6Route = HasGlobalIPv6Route();

            // Tier 1: IPv6 + Port 856 (Strict Web PKI CA) with 1000ms race window
            if (hasV6Route && v6Addrs.Count > 0)
            {
                using var raceCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                raceCts.CancelAfter(_options.IPv6RaceWindow);

                try
                {
                    var endpoint = new IPEndPoint(v6Addrs[0], _options.PortStrict);
                    return await DialQuicAsync(endpoint, isDisaster: false, raceCts.Token).ConfigureAwait(false);
                }
                catch (Exception ex) when (IsCertificateException(ex) && _options.PinnedSpkiHashes.Count > 0)
                {
                    // Instant 0ms failover on certificate mismatch to Tier 3 on same IPv6 stack
                    try
                    {
                        var endpointD = new IPEndPoint(v6Addrs[0], _options.PortDisaster);
                        return await DialQuicAsync(endpointD, isDisaster: true, cancellationToken).ConfigureAwait(false);
                    }
                    catch { /* Continue to IPv4 */ }
                }
                catch
                {
                    // Fall through to Tier 2 on timeout or unreachable
                }
            }

            // Tier 2: IPv4 + Port 856 (Strict Web PKI CA)
            if (v4Addrs.Count > 0)
            {
                try
                {
                    var endpoint = new IPEndPoint(v4Addrs[0], _options.PortStrict);
                    return await DialQuicAsync(endpoint, isDisaster: false, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (IsCertificateException(ex) && _options.PinnedSpkiHashes.Count > 0)
                {
                    // Instant failover to Tier 4
                    try
                    {
                        var endpointD = new IPEndPoint(v4Addrs[0], _options.PortDisaster);
                        return await DialQuicAsync(endpointD, isDisaster: true, cancellationToken).ConfigureAwait(false);
                    }
                    catch { /* Continue */ }
                }
                catch
                {
                    // Continue to disaster tier
                }
            }

            // Tier 3: IPv6 + Port 855 (Disaster Recovery SPKI Pinning)
            if (hasV6Route && v6Addrs.Count > 0 && _options.PinnedSpkiHashes.Count > 0)
            {
                try
                {
                    var endpoint = new IPEndPoint(v6Addrs[0], _options.PortDisaster);
                    return await DialQuicAsync(endpoint, isDisaster: true, cancellationToken).ConfigureAwait(false);
                }
                catch { /* Continue */ }
            }

            // Tier 4: IPv4 + Port 855 (Disaster Recovery SPKI Pinning)
            if (v4Addrs.Count > 0 && _options.PinnedSpkiHashes.Count > 0)
            {
                try
                {
                    var endpoint = new IPEndPoint(v4Addrs[0], _options.PortDisaster);
                    return await DialQuicAsync(endpoint, isDisaster: true, cancellationToken).ConfigureAwait(false);
                }
                catch { /* Final fail */ }
            }

            throw new SocketException((int)SocketError.NetworkUnreachable);
        }

        private async Task<QuicConnection> DialQuicAsync(IPEndPoint endpoint, bool isDisaster, CancellationToken ct)
        {
            var sslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = _options.ServerHost,
                ApplicationProtocols = new List<SslApplicationProtocol> { new(LcpConstants.AlpnProtocol) },
            };

            if (isDisaster)
            {
                // SPKI Pinning with full ASN.1 SubjectPublicKeyInfo export
                sslOptions.RemoteCertificateValidationCallback = (sender, cert, chain, errors) =>
                {
                    if (cert is not X509Certificate2 x509) return false;
                    byte[] spkiHash = SHA256.HashData(x509.PublicKey.ExportSubjectPublicKeyInfo());
                    string hexHash = Convert.ToHexString(spkiHash);
                    return _options.PinnedSpkiHashes.Contains(hexHash);
                };
            }
            else if (_options.InsecureSkipCA)
            {
                sslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
            }

            var quicOptions = new QuicClientConnectionOptions
            {
                RemoteEndPoint = endpoint,
                ClientAuthenticationOptions = sslOptions,
                DefaultStreamErrorCode = 0x00,
                DefaultCloseErrorCode = 0x00,
                MaxInboundBidirectionalStreams = 100,
            };

            return await QuicConnection.ConnectAsync(quicOptions, ct).ConfigureAwait(false);
        }

        public async Task<QuicStream> OpenStreamAsync(CancellationToken cancellationToken = default)
        {
            var conn = await ConnectAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                return await conn.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                // Stale connection reset & retry once
                await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    if (_connection != null)
                    {
                        await _connection.DisposeAsync().ConfigureAwait(false);
                        _connection = null;
                    }
                }
                finally
                {
                    _lock.Release();
                }

                var newConn = await ConnectAsync(cancellationToken).ConfigureAwait(false);
                return await newConn.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cancellationToken).ConfigureAwait(false);
            }
        }

        private static async Task<(List<IPAddress> v6, List<IPAddress> v4)> ResolveAddressesAsync(string host, CancellationToken ct)
        {
            var v6 = new List<IPAddress>();
            var v4 = new List<IPAddress>();

            if (IPAddress.TryParse(host, out var literal))
            {
                if (literal.AddressFamily == AddressFamily.InterNetwork) v4.Add(literal);
                else if (literal.AddressFamily == AddressFamily.InterNetworkV6) v6.Add(literal);
                return (v6, v4);
            }

            try
            {
                var ips = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
                foreach (var ip in ips)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork && !IsFakeIP(ip))
                    {
                        v4.Add(ip);
                    }
                    else if (ip.AddressFamily == AddressFamily.InterNetworkV6 && IsGlobalUnicastIPv6(ip))
                    {
                        v6.Add(ip);
                    }
                }
            }
            catch { /* Ignore DNS failure; fallback IP will be used */ }

            return (v6, v4);
        }

        private static bool IsFakeIP(IPAddress ip)
        {
            var bytes = ip.GetAddressBytes();
            return bytes.Length == 4 && bytes[0] == 198 && (bytes[1] & 0xFE) == 18;
        }

        private static bool IsGlobalUnicastIPv6(IPAddress ip)
        {
            var bytes = ip.GetAddressBytes();
            return bytes.Length == 16 && (bytes[0] & 0xE0) == 0x20;
        }

        private static bool HasGlobalIPv6Route()
        {
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                        continue;

                    foreach (var addr in nic.GetIPProperties().UnicastAddresses)
                    {
                        if (addr.Address.AddressFamily == AddressFamily.InterNetworkV6 && IsGlobalUnicastIPv6(addr.Address))
                        {
                            return true;
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        private static bool IsCertificateException(Exception ex)
        {
            var msg = ex.Message.ToLowerInvariant();
            return msg.Contains("certificate") || msg.Contains("x509") || msg.Contains("ssl") || msg.Contains("remotecertificate");
        }

        public async ValueTask DisposeAsync()
        {
            await _lock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (_connection != null)
                {
                    await _connection.DisposeAsync().ConfigureAwait(false);
                    _connection = null;
                }
            }
            finally
            {
                _lock.Release();
            }
        }
    }
}
