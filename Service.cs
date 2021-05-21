using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace FindCCU
{
    public class Service
    {
        private const string DEFAULT_ADDRESS = "224.0.0.1";
        private const string BROADCAST_ADDRESS = "255.255.255.255";
        private const int DEFAULT_PORT = 43439;
        private const int RESEND_WAIT_TIME = 100;
        private const int TTL = 5;
        private readonly int _retryCount;
        private readonly int _timeout;

        public Service(int timeout = 2000, int retryCount = 2)
        {
            _timeout = timeout;
            _retryCount = retryCount;
        }

        public Task<List<CCU>> SearchAllInterfaces(string localIp)
        {
            return Task.Run(async () =>
            {
                var responses = new List<CCU>();
                var nics = NetworkInterface.GetAllNetworkInterfaces();
                var wereThereMulticastAdapters = false;
                foreach (var adapter in nics)
                {
                    //if (!adapter.GetIPProperties().MulticastAddresses.Any())
                    //    continue; // most of VPN adapters will be skipped
                    if (!adapter.SupportsMulticast)
                        continue; // multicast is meaningless for this type of connection
                    if (OperationalStatus.Up != adapter.OperationalStatus)
                        continue; // this adapter is off or not connected
                    var p = adapter.GetIPProperties().GetIPv4Properties();
                    if (null == p)
                        continue; // IPv4 is not configured on this adapter

                    try
                    {
                        wereThereMulticastAdapters = true;
                        var ccus = await Search(localIp, p.Index);
                        foreach (var ccu in ccus)
                            if (!responses.Any(x => x.Host == ccu.Host))
                                responses.Add(ccu);
                    }
                    catch (SocketException)
                    {
                    }
                }

                if (!wereThereMulticastAdapters)
                    throw new Exception("Code: 9919, no multi cast adapters were found");

                return responses;
            });
        }

        private Task<List<CCU>> Search(string localIp, int multicastInterfaceIndex = -1)
        {
            return Task.Run(async () =>
            {
                var responses = new List<CCU>();
                var multicastIpAddress = IPAddress.Parse(DEFAULT_ADDRESS);
                var localIpAddress = IPAddress.Parse(localIp);

                var groupEP = new IPEndPoint(multicastIpAddress, DEFAULT_PORT);
                EndPoint remoteEndpoint = new IPEndPoint(IPAddress.Any, 0);
                EndPoint multicastEndPoint = new IPEndPoint(multicastIpAddress, DEFAULT_PORT);

                var buffer = new byte[1024];
                var receivedBytes = 0;

                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                socket.Bind(remoteEndpoint);
                socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, TTL);
                socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership,
                    new MulticastOption(multicastIpAddress, localIpAddress));
                if (multicastInterfaceIndex >= 0)
                    socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface,
                        IPAddress.HostToNetworkOrder(multicastInterfaceIndex));

                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, 1);

                socket.SendTimeout = _timeout;
                socket.ReceiveTimeout = _timeout;

                var message = GetMessage();
                var currentTryLoop = 0;

                while (currentTryLoop < _retryCount)
                {
                    message = GetMessage();
                    socket.SendTo(message, 0, message.Length, SocketFlags.None, multicastEndPoint);
                    currentTryLoop++;

                    try
                    {
                        receivedBytes = socket.ReceiveFrom(buffer, ref remoteEndpoint);
                    }
                    catch (SocketException ex)
                    {
                        Debug.WriteLine(ex.Message + "\r\n" + ex.StackTrace);
                    }

                    if (receivedBytes > 0)
                        responses.Add(new CCU
                        {
                            Host = (remoteEndpoint as IPEndPoint)?.Address?.ToString(),
                            Payload = Encoding.ASCII.GetString(buffer, 0, receivedBytes)
                        });
                    await Task.Delay(RESEND_WAIT_TIME);
                }

                socket.Close();
                return responses;
            });
        }

        private byte[] GetMessage()
        {
            var senderId = new Random().Next(int.MinValue, int.MaxValue) & 0xFFFFFF;
            var sender = (senderId >> (1 * 8)) & 0xFF;
            var deviceTypeId = "*";
            var sendCounter = 1;
            var serialNumber = "";
            var payload = "*";
            var message = $"2{sender}{sendCounter}{deviceTypeId}0{serialNumber}0{UdpOpcode.Identify}{payload}";

            return Encoding.UTF8.GetBytes(message);
        }

        private enum UdpOpcode
        {
            Identify = 73,
            GetConfig = 99,
            SetConfig = 67,
            GetNetworkAddress = 110,
            Reboot = 82,
            EnterBootloader = 66,
            EnterApplication = 65,
            InitUpdate = 85,
            WriteUpdate = 87,
            GetTestStatus = 116,
            SetTestStatus = 84,
            Crypt = 42,
            FactoryReset = 70,
            InitKeyExchange = 75,
            KeyExchange = 69,
            ProductionTest = 80,
            GetDeviceSpecificConfigStructure = 115,
            GetDeviceSpecificConfig = 100,
            SetDeviceSpecificConfig = 68
        }
    }
}