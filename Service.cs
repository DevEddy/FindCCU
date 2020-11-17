using System;
using System.Collections.Generic;
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
        const string DEFAULT_ADDRESS = "224.0.0.1";
        const string BROADCAST_ADDRESS = "255.255.255.255";
        const int DEFAULT_PORT = 43439;
        readonly int _retryCount;
        const int RESEND_WAIT_TIME = 100;
        const int TTL = 5;
        readonly int _timeout;

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
                    if (!adapter.GetIPProperties().MulticastAddresses.Any())
                        continue; // most of VPN adapters will be skipped
                    if (!adapter.SupportsMulticast)
                        continue; // multicast is meaningless for this type of connection
                    if (OperationalStatus.Up != adapter.OperationalStatus)
                        continue; // this adapter is off or not connected
                    IPv4InterfaceProperties p = adapter.GetIPProperties().GetIPv4Properties();
                    if (null == p)
                        continue; // IPv4 is not configured on this adapter

                    try
                    {
                        wereThereMulticastAdapters = true;
                        var ccus = await Search(localIp, p.Index);
                        foreach (var ccu in ccus)
                        {
                            if (!responses.Any(x => x.Host == ccu.Host))
                                responses.Add(ccu);
                        }
                    }
                    catch (SocketException)
                    {
                        continue;
                    }
                }
                if (!wereThereMulticastAdapters)
                    throw new Exception($"Code: 9919, no multi cast adapters were found");

                return responses;
            });
        }

        Task<List<CCU>> Search(string localIp, int multicastInterfaceIndex = -1)
        {
            return Task.Run(async () =>
            {
                var responses = new List<CCU>();
                var multicastIpAddress = IPAddress.Parse(DEFAULT_ADDRESS);
                var localIpAddress = IPAddress.Parse(localIp);

                IPEndPoint groupEP = new IPEndPoint(multicastIpAddress, DEFAULT_PORT);
                EndPoint remoteEndpoint = new IPEndPoint(IPAddress.Any, 0);
                EndPoint multicastEndPoint = new IPEndPoint(multicastIpAddress, DEFAULT_PORT);

                var buffer = new byte[1024];
                int receivedBytes = 0;

                using Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                socket.Bind(remoteEndpoint);
                socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, TTL);
                socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, new MulticastOption(multicastIpAddress, localIpAddress));
                if (multicastInterfaceIndex >= 0)
                    socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, IPAddress.HostToNetworkOrder(multicastInterfaceIndex));

                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, 1);

                socket.SendTimeout = _timeout;
                socket.ReceiveTimeout = _timeout;

                var message = GetMessage();
                int currentTryLoop = 0;

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
                        System.Diagnostics.Debug.WriteLine(ex.Message + "\r\n" + ex.StackTrace);
                    }
                    if (receivedBytes > 0)
                    {
                        responses.Add(new CCU
                        {
                            Host = (remoteEndpoint as IPEndPoint)?.Address?.ToString(),
                            Payload = Encoding.ASCII.GetString(buffer, 0, receivedBytes)
                        });
                    }
                    await Task.Delay(RESEND_WAIT_TIME);
                }
                socket.Close();
                return responses;
            });
        }

        byte[] GetMessage()
        {
            var senderId = new Random().Next(int.MinValue, int.MaxValue) & 0xFFFFFF;
            var sender = senderId >> 1 * 8 & 0xFF;
            var deviceTypeId = "*";
            var sendCounter = 1;
            var serialNumber = "";
            var payload = "*";
            var message = $"2{sender}{sendCounter}{deviceTypeId}0{serialNumber}0{UdpOpcode.Identify}{payload}";

            return Encoding.UTF8.GetBytes(message);
        }

        enum UdpOpcode
        {
            Identify = (byte)73,
            GetConfig = (byte)99,
            SetConfig = (byte)67,
            GetNetworkAddress = (byte)110,
            Reboot = (byte)82,
            EnterBootloader = (byte)66,
            EnterApplication = ((byte)65),
            InitUpdate = ((byte)85),
            WriteUpdate = ((byte)87),
            GetTestStatus = ((byte)116),
            SetTestStatus = ((byte)84),
            Crypt = ((byte)42),
            FactoryReset = ((byte)70),
            InitKeyExchange = ((byte)75),
            KeyExchange = ((byte)69),
            ProductionTest = ((byte)80),
            GetDeviceSpecificConfigStructure = ((byte)115),
            GetDeviceSpecificConfig = ((byte)100),
            SetDeviceSpecificConfig = ((byte)68)
        }
    }
}
