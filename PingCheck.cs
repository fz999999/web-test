using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

public static class NetProbe
{
    public class HostItem { public string Host; public int Port; public string Label; public string Scheme = "https"; }
    public class Config
    {
        public List<HostItem> Hosts = new List<HostItem>();
        public int PingTimeoutMs = 1200;   // 单次 ping 超时
        public int HttpTimeoutMs = 6000;   // TCP/TLS/HTTP 超时
        public int Tries = 2;              // ping 次数
        public bool IcmpEnabled = true;    // 是否顺带做 ICMP 参考
        public SslProtocols TlsProtos = SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls;
        public string Proxy = "auto";      // auto | direct | http://host:port | socks5://host:port
        public ProxyInfo Resolved = null;
        public string ProxyNote = "";
    }
    public class Result
    {
        public HostItem Target;
        public bool Ok;
        public string Mode = "";
        public string Code = "";
        public long HttpMs = -1;
        public long IcmpMs = -1;
        public long TcpMs = -1;
        public long TlsMs = -1;
        public string Ip = "";
        public string Via = "直连";
        public string Status = "";
        public string Remark = "";
        public int Recv;
        public int Sent;
    }

    public static string ConfigPath()
    {
        return Path.Combine(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "QuickerPing"), "hosts.txt");
    }

    // 取值：支持行内 # 注释，以及 "值 + 空格 + 说明文字" 的写法（只取第一段）
    private static string CleanValue(string v)
    {
        if (v == null) return "";
        int h = v.IndexOf('#');
        if (h >= 0) v = v.Substring(0, h);
        v = v.Trim();
        int sp = v.IndexOfAny(new char[] { ' ', '\t' });
        if (sp > 0) v = v.Substring(0, sp);
        return v.Trim();
    }

    public static Config LoadConfig()
    {
        string path = ConfigPath();
        Config cfg = new Config();
        try
        {
            if (!File.Exists(path))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                StringBuilder t = new StringBuilder();
                t.AppendLine("# 一行一个域名，保存后重新运行动作即可生效（# 开头是注释）");
                t.AppendLine("#   example.com            测 HTTPS(443) 能不能真正打开，同时 ping 作参考");
                t.AppendLine("#   example.com:8443       指定端口");
                t.AppendLine("#   x.com 推特              可选显示名，用空格或逗号分隔");
                t.AppendLine("# tcp/host:port            只测端口通不通（SSH 等非 HTTPS 端口用这个）");
                t.AppendLine("#");
                t.AppendLine("# ---- git / GitHub 需要的端点（按需取消注释） ----");
                t.AppendLine("# github.com                    网页 + clone/push (HTTPS)");
                t.AppendLine("# api.github.com                API / 令牌校验 / 设备码登录");
                t.AppendLine("# codeload.github.com           下载源码包");
                t.AppendLine("# raw.githubusercontent.com     raw 文件");
                t.AppendLine("# objects.githubusercontent.com 附件 / LFS 对象");
                t.AppendLine("# github.githubassets.com       网页静态资源");
                t.AppendLine("# tcp/github.com:22             SSH 直连方式");
                t.AppendLine("# tcp/ssh.github.com:443        22 被封时的 SSH over 443");
                t.AppendLine("#");
                t.AppendLine("# timeout=1200             单次 ping 超时(毫秒)");
                t.AppendLine("# http_timeout=6000        HTTPS 连接/读取超时(毫秒)");
                t.AppendLine("# tries=2                  每个域名 ping 次数");
                t.AppendLine("# icmp=on                  是否顺带 ping（只作参考，关掉更快）");
                t.AppendLine("proxy=auto");
                t.AppendLine("# proxy=direct           强制直连");
                t.AppendLine("# proxy=socks5://127.0.0.1:10808   指定 SOCKS5（v2rayN 默认端口）");
                t.AppendLine("# proxy=http://127.0.0.1:10809     指定 HTTP 代理");
                t.AppendLine();
                t.AppendLine("google.com");
                t.AppendLine("github.com");
                File.WriteAllText(path, t.ToString(), new UTF8Encoding(false));
            }

            foreach (string raw in File.ReadAllLines(path, Encoding.UTF8))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#") || line.StartsWith("//")) continue;

                string scheme = "https";

                if (line.StartsWith("timeout="))
                {
                    int v; if (int.TryParse(CleanValue(line.Substring(8)), out v) && v >= 100) cfg.PingTimeoutMs = v;
                    continue;
                }
                if (line.StartsWith("http_timeout="))
                {
                    int v; if (int.TryParse(CleanValue(line.Substring(13)), out v) && v >= 500) cfg.HttpTimeoutMs = v;
                    continue;
                }
                if (line.StartsWith("tries="))
                {
                    int v; if (int.TryParse(CleanValue(line.Substring(6)), out v) && v >= 1) cfg.Tries = v;
                    continue;
                }
                if (line.StartsWith("icmp="))
                {
                    string v = CleanValue(line.Substring(5)).ToLower();
                    cfg.IcmpEnabled = !(v == "0" || v == "off" || v == "false" || v == "no");
                    continue;
                }
                if (line.StartsWith("proxy="))
                {
                    cfg.Proxy = CleanValue(line.Substring(6));
                    continue;
                }

                if (line.StartsWith("tcp/", StringComparison.OrdinalIgnoreCase)) { scheme = "tcp"; line = line.Substring(4).Trim(); }
                else if (line.StartsWith("https/", StringComparison.OrdinalIgnoreCase)) { scheme = "https"; line = line.Substring(6).Trim(); }

                string name = null;
                int sp = line.IndexOfAny(new char[] { ' ', '\t', ',' });
                if (sp > 0) { name = line.Substring(sp + 1).Trim(); line = line.Substring(0, sp).Trim(); }

                int port = 443;
                int colon = line.LastIndexOf(':');
                if (colon > 0 && colon < line.Length - 1)
                {
                    int p;
                    if (int.TryParse(line.Substring(colon + 1), out p) && p > 0 && p <= 65535)
                    {
                        port = p;
                        line = line.Substring(0, colon).Trim();
                    }
                }
                if (line.Length == 0) continue;

                HostItem h = new HostItem();
                h.Scheme = scheme;
                h.Host = line;
                h.Port = port;
                h.Label = string.IsNullOrEmpty(name) ? line : name;
                cfg.Hosts.Add(h);
            }
        }
        catch { }

        if (cfg.Hosts.Count == 0)
        {
            HostItem h = new HostItem(); h.Host = "google.com"; h.Port = 443; h.Label = "google.com"; cfg.Hosts.Add(h);
            HostItem h2 = new HostItem(); h2.Host = "github.com"; h2.Port = 443; h2.Label = "github.com"; cfg.Hosts.Add(h2);
        }
        return cfg;
    }

    public static bool PingOnce(string host, int timeoutMs, out long ms, out string ip)
    {
        ms = -1; ip = "";
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo("ping.exe", "-n 1 -w " + timeoutMs + " " + host);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            using (Process p = Process.Start(psi))
            {
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(timeoutMs + 5000);

                Match mIp = Regex.Match(output, @"\[(\d{1,3}(?:\.\d{1,3}){3})\]");
                if (mIp.Success) ip = mIp.Groups[1].Value;
                if (output.IndexOf("TTL", StringComparison.OrdinalIgnoreCase) < 0) return false;

                Match mMs = Regex.Match(output, @"[=<]\s*(\d+)\s*ms", RegexOptions.IgnoreCase);
                ms = mMs.Success ? long.Parse(mMs.Groups[1].Value) : 0;
                return true;
            }
        }
        catch { return false; }
    }

    public class ProxyInfo { public string Kind = "direct"; public string Host = ""; public int Port = 0; }

    // 解析 "socks5://host:port" / "http://host:port" / "host:port"（不带 scheme 时标记为待探测）
    private static ProxyInfo ParseExplicit(string raw)
    {
        ProxyInfo p = new ProxyInfo();
        string s = (raw == null) ? "" : raw.Trim();
        if (s.StartsWith("socks5://", StringComparison.OrdinalIgnoreCase)) { p.Kind = "socks5"; s = s.Substring(9); }
        else if (s.StartsWith("socks://", StringComparison.OrdinalIgnoreCase)) { p.Kind = "socks5"; s = s.Substring(8); }
        else if (s.StartsWith("socks5:", StringComparison.OrdinalIgnoreCase)) { p.Kind = "socks5"; s = s.Substring(7); }
        else if (s.StartsWith("socks:", StringComparison.OrdinalIgnoreCase)) { p.Kind = "socks5"; s = s.Substring(6); }
        else if (s.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) { p.Kind = "http"; s = s.Substring(7); }
        else if (s.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) { p.Kind = "http"; s = s.Substring(8); }
        else if (s.StartsWith("http:", StringComparison.OrdinalIgnoreCase)) { p.Kind = "http"; s = s.Substring(5); }
        else p.Kind = "guess";

        s = s.Trim().TrimEnd('/');
        string host = s; int port = 0;
        int colon = s.LastIndexOf(':');
        if (colon > 0)
        {
            host = s.Substring(0, colon).Trim();
            int.TryParse(s.Substring(colon + 1).Trim(), out port);
        }
        p.Host = host;
        p.Port = port > 0 ? port : (p.Kind == "socks5" ? 1080 : 8080);
        return p;
    }

    private static string ReadSystemProxy()
    {
        try
        {
            using (Microsoft.Win32.RegistryKey k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings"))
            {
                if (k == null) return "";
                object sv = k.GetValue("ProxyServer");
                // 注意：有些代理软件（如 v2rayN 未点“系统代理”时）只写 ProxyServer、ProxyEnable 仍为 0，
                // 所以这里不只看开关，直接把地址拿出来实测，能通就用。
                if (sv != null)
                {
                        string v = sv.ToString();
                        if (v.IndexOf('=') >= 0)
                        {
                            foreach (string part in v.Split(';'))
                            {
                                string t = part.Trim();
                                if (t.StartsWith("https=", StringComparison.OrdinalIgnoreCase) || t.StartsWith("http=", StringComparison.OrdinalIgnoreCase))
                                    return t.Substring(t.IndexOf('=') + 1);
                            }
                            return "";
                        }
                    return v;
                }
            }
        }
        catch { }
        return "";
    }

    private static ProxyInfo MakeProxy(string kind, string host, int port)
    {
        ProxyInfo p = new ProxyInfo();
        p.Kind = kind; p.Host = host; p.Port = port;
        return p;
    }

    private static bool TestSocks5(string phost, int pport, string thost, int tport, int timeoutMs)
    {
        TcpClient c = null;
        try
        {
            List<IPAddress> ips = ResolveHost(phost);
            if (ips.Count == 0) return false;
            c = new TcpClient();
            if (!ConnectWithTimeout(c, ips[0], pport, timeoutMs)) return false;
            return Socks5Handshake(c.GetStream(), thost, tport, timeoutMs);
        }
        catch { return false; }
        finally { try { if (c != null) c.Close(); } catch { } }
    }

    private static bool TestHttpProxy(string phost, int pport, string thost, int tport, int timeoutMs)
    {
        TcpClient c = null;
        try
        {
            List<IPAddress> ips = ResolveHost(phost);
            if (ips.Count == 0) return false;
            c = new TcpClient();
            if (!ConnectWithTimeout(c, ips[0], pport, timeoutMs)) return false;
            HostItem h = new HostItem();
            h.Host = thost; h.Port = tport;
            return HttpProxyHandshake(c.GetStream(), h, timeoutMs);
        }
        catch { return false; }
        finally { try { if (c != null) c.Close(); } catch { } }
    }

    // 实测这个端点到底是 SOCKS5 还是 HTTP 代理（都能试，取能用的那种）
    private static ProxyInfo VerifyEndpoint(ProxyInfo ep, string targetHost, int targetPort, int timeoutMs)
    {
        ProxyInfo p = new ProxyInfo();
        p.Host = ep.Host; p.Port = ep.Port;
        int probe = Math.Max(3000, Math.Min(timeoutMs, 8000));

        if (ep.Kind == "socks5" || ep.Kind == "guess")
            if (TestSocks5(ep.Host, ep.Port, targetHost, targetPort, probe)) { p.Kind = "socks5"; return p; }
        if (ep.Kind == "http" || ep.Kind == "guess")
            if (TestHttpProxy(ep.Host, ep.Port, targetHost, targetPort, probe)) { p.Kind = "http"; return p; }
        if (ep.Kind == "socks5")
            if (TestHttpProxy(ep.Host, ep.Port, targetHost, targetPort, probe)) { p.Kind = "http"; return p; }
        if (ep.Kind == "http")
            if (TestSocks5(ep.Host, ep.Port, targetHost, targetPort, probe)) { p.Kind = "socks5"; return p; }

        p.Kind = "unavailable";
        return p;
    }

    // 扫本机常见代理端口（v2rayN 10808/10809、Clash 7890/7891/7897、其它 1080/8889…）
    private static ProxyInfo ScanLocalProxies(string thost, int tport, int probeMs)
    {
        int[] ports = new int[] { 10808, 10809, 7890, 7891, 7897, 1080, 8889, 8888, 2080, 20171, 1081 };

        foreach (int port in ports)
            if (TestSocks5("127.0.0.1", port, thost, tport, probeMs))
                return MakeProxy("socks5", "127.0.0.1", port);
        foreach (int port in ports)
            if (TestHttpProxy("127.0.0.1", port, thost, tport, probeMs))
                return MakeProxy("http", "127.0.0.1", port);
        return null;
    }

    // 解析本次实际使用的代理；结果缓存到 cfg，并写一句说明到 cfg.ProxyNote
    public static ProxyInfo ResolveProxy(Config cfg)
    {
        if (cfg.Resolved != null) return cfg.Resolved;

        string raw = (cfg.Proxy == null) ? "" : cfg.Proxy.Trim();
        if (raw.Length == 0) raw = "auto";
        string thost = (cfg.Hosts.Count > 0) ? cfg.Hosts[0].Host : "www.baidu.com";
        int tport = (cfg.Hosts.Count > 0) ? cfg.Hosts[0].Port : 443;

        ProxyInfo px = new ProxyInfo();
        if (raw.Equals("direct", StringComparison.OrdinalIgnoreCase) || raw.Equals("none", StringComparison.OrdinalIgnoreCase))
        {
            px.Kind = "direct";
            cfg.ProxyNote = "直连（配置指定 direct）";
        }
        else if (raw.Equals("auto", StringComparison.OrdinalIgnoreCase))
        {
            string sys = ReadSystemProxy();
            if (sys.Length > 0)
            {
                ProxyInfo sp = VerifyEndpoint(ParseExplicit(sys), thost, tport, cfg.HttpTimeoutMs);
                if (sp.Kind == "socks5" || sp.Kind == "http")
                {
                    px = sp;
                    cfg.ProxyNote = "系统代理 " + sys + " → " + sp.Kind;
                }
            }
            if (px.Kind != "socks5" && px.Kind != "http")
            {
                ProxyInfo found = ScanLocalProxies(thost, tport, Math.Max(3000, Math.Min(cfg.HttpTimeoutMs, 8000)));
                if (found != null)
                {
                    px = found;
                    cfg.ProxyNote = "自动探测 → " + found.Kind + " " + found.Host + ":" + found.Port;
                }
            }
            if (px.Kind != "socks5" && px.Kind != "http")
            {
                px = new ProxyInfo();
                px.Kind = "direct";
                cfg.ProxyNote = "未发现可用代理 → 直连";
            }
        }
        else
        {
            ProxyInfo ep = ParseExplicit(raw);
            px = VerifyEndpoint(ep, thost, tport, cfg.HttpTimeoutMs);
            if (px.Kind == "unavailable")
            {
                px = new ProxyInfo();
                px.Kind = "direct";
                cfg.ProxyNote = "指定代理不可用（" + raw + "）→ 直连";
            }
            else
            {
                cfg.ProxyNote = raw + " → " + px.Kind;
            }
        }

        cfg.Resolved = px;
        return px;
    }

    private static bool ConnectWithTimeout(TcpClient client, IPAddress ip, int port, int timeoutMs)
    {
        try
        {
            IAsyncResult ar = client.BeginConnect(ip, port, null, null);
            if (!ar.AsyncWaitHandle.WaitOne(timeoutMs, false)) { try { client.Close(); } catch { } return false; }
            client.EndConnect(ar);
            client.ReceiveTimeout = timeoutMs;
            client.SendTimeout = timeoutMs;
            return client.Connected;
        }
        catch { return false; }
    }

    private static bool HttpProxyHandshake(Stream s, HostItem h, int timeoutMs)
    {
        try
        {
            s.ReadTimeout = timeoutMs; s.WriteTimeout = timeoutMs;
            string req = "CONNECT " + h.Host + ":" + h.Port + " HTTP/1.1\r\nHost: " + h.Host + ":" + h.Port + "\r\nProxy-Connection: keep-alive\r\n\r\n";
            byte[] b = Encoding.ASCII.GetBytes(req);
            s.Write(b, 0, b.Length); s.Flush();
            string line = ReadLine(s);
            return line.StartsWith("HTTP/") && line.IndexOf(" 200") > 0;
        }
        catch { return false; }
    }

    private static bool Socks5Handshake(Stream s, string host, int port, int timeoutMs)
    {
        try
        {
            s.ReadTimeout = timeoutMs; s.WriteTimeout = timeoutMs;
            s.Write(new byte[] { 5, 1, 0 }, 0, 3); s.Flush();
            byte[] resp = new byte[2];
            if (!ReadExact(s, resp, 2) || resp[0] != 5 || resp[1] != 0) return false;

            byte[] hostBytes = Encoding.ASCII.GetBytes(host);
            byte[] req = new byte[7 + hostBytes.Length];
            req[0] = 5; req[1] = 1; req[2] = 0; req[3] = 3;
            req[4] = (byte)hostBytes.Length;
            Array.Copy(hostBytes, 0, req, 5, hostBytes.Length);
            req[5 + hostBytes.Length] = (byte)(port >> 8);
            req[6 + hostBytes.Length] = (byte)(port & 0xFF);
            s.Write(req, 0, req.Length); s.Flush();

            byte[] head = new byte[4];
            if (!ReadExact(s, head, 4) || head[1] != 0) return false;
            int skip = 0;
            if (head[3] == 1) skip = 4;
            else if (head[3] == 4) skip = 16;
            else if (head[3] == 3)
            {
                byte[] lb = new byte[1];
                if (!ReadExact(s, lb, 1)) return false;
                skip = lb[0];
            }
            byte[] rest = new byte[skip + 2];
            return ReadExact(s, rest, rest.Length);
        }
        catch { return false; }
    }

    private static bool ReadExact(Stream s, byte[] buf, int count)
    {
        int got = 0;
        while (got < count)
        {
            int n = s.Read(buf, got, count - got);
            if (n <= 0) return false;
            got += n;
        }
        return true;
    }

    private static string ReadLine(Stream s)
    {
        StringBuilder sb = new StringBuilder();
        try
        {
            while (sb.Length < 512)
            {
                int c = s.ReadByte();
                if (c < 0) break;
                if (c == 13) continue;
                if (c == 10) break;
                sb.Append((char)c);
            }
        }
        catch { }
        return sb.ToString();
    }

    private static List<IPAddress> ResolveHost(string host)
    {
        List<IPAddress> list = new List<IPAddress>();
        try
        {
            foreach (IPAddress a in Dns.GetHostAddresses(host))
                if (a.AddressFamily == AddressFamily.InterNetwork) list.Add(a);
        }
        catch { }
        return list;
    }

    public static void RunHttp(HostItem h, Config cfg, Result r)
    {
        Stopwatch sw = Stopwatch.StartNew();
        TcpClient client = null;
        try
        {
            ProxyInfo px = ResolveProxy(cfg);
            List<IPAddress> targets;

            if (px.Kind == "direct")
            {
                targets = ResolveHost(h.Host);
                if (targets.Count == 0) { r.Mode = "DNS 失败"; r.Remark = "域名解析失败"; return; }
                if (targets.Count > 3) targets = targets.GetRange(0, 3);
                r.Via = "直连";
            }
            else
            {
                targets = ResolveHost(px.Host);
                if (targets.Count == 0) { r.Mode = "代理失败"; r.Remark = "代理地址无法解析：" + px.Host; return; }
                targets = targets.GetRange(0, 1);
                r.Via = px.Kind + " " + px.Host + ":" + px.Port;
            }

            string bestMode = "";
            string bestRemark = "";

            foreach (IPAddress ip in targets)
            {
                r.Ip = (px.Kind == "direct") ? ip.ToString() : "";
                int port = (px.Kind == "direct") ? h.Port : px.Port;

                client = new TcpClient();
                if (!ConnectWithTimeout(client, ip, port, cfg.HttpTimeoutMs))
                {
                    try { client.Close(); } catch { }
                    client = null;
                    if (px.Kind == "direct") { bestMode = "TCP 失败"; bestRemark = "端口 " + h.Port + " 连不上（" + r.Ip + "）"; }
                    else { bestMode = "代理失败"; bestRemark = "连不上代理 " + px.Host + ":" + px.Port; }
                    continue;
                }

                if (px.Kind != "direct")
                {
                    Stream ps = client.GetStream();
                    bool hs = (px.Kind == "http")
                        ? HttpProxyHandshake(ps, h, cfg.HttpTimeoutMs)
                        : Socks5Handshake(ps, h.Host, h.Port, cfg.HttpTimeoutMs);
                    if (!hs)
                    {
                        try { client.Close(); } catch { }
                        client = null;
                        bestMode = "代理失败";
                        bestRemark = "代理握手失败（" + r.Via + "）";
                        continue;
                    }
                }

                if (h.Scheme == "tcp")
                {
                    r.Ok = true;
                    r.TcpMs = sw.ElapsedMilliseconds;
                    r.HttpMs = r.TcpMs;
                    r.Mode = "TCP 通";
                    r.Remark = (px.Kind == "direct")
                        ? ("端口 " + h.Port + " 可连接（tcp/ 只测端口）")
                        : ("经 " + r.Via + " 连上端口 " + h.Port);
                    try { client.Close(); } catch { }
                    client = null;
                    return;
                }

                r.TcpMs = sw.ElapsedMilliseconds;

                string mode; string remark;
                long httpMs = -1; long tlsMs = -1;
                bool ok = TlsAndHttp(client, h, cfg, out mode, out remark, out httpMs, out tlsMs);
                bestMode = mode;
                bestRemark = remark;
                if (ok)
                {
                    r.Ok = true;
                    r.HttpMs = httpMs;
                    r.TlsMs = tlsMs;
                    r.Mode = mode;
                    r.Remark = (px.Kind == "direct") ? remark : ("经 " + r.Via + "；" + remark);
                    try { client.Close(); } catch { }
                    client = null;
                    return;
                }

                try { client.Close(); } catch { }
                client = null;
            }

            r.Mode = (bestMode.Length > 0) ? bestMode : "TCP 失败";
            r.Remark = bestRemark;
        }
        catch (Exception ex)
        {
            r.Mode = "异常";
            r.Remark = Short(ex);
        }
        finally { try { if (client != null) client.Close(); } catch { } }
    }

    // 在已连通的 socket 上做 TLS 握手 + HTTP 请求；成功即把结果写进 r
    private static bool TlsAndHttp(TcpClient client, HostItem h, Config cfg, out string mode, out string remark, out long httpMs, out long tlsMs)
    {
        mode = ""; remark = ""; httpMs = -1; tlsMs = -1;
        Stopwatch sw = Stopwatch.StartNew();
        try
        {
            Stream raw = client.GetStream();
            SslStream ssl = new SslStream(raw, false, new RemoteCertificateValidationCallback(
                delegate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) { return true; }));
            ssl.ReadTimeout = cfg.HttpTimeoutMs;
            ssl.WriteTimeout = cfg.HttpTimeoutMs;

            try { ssl.AuthenticateAsClient(h.Host, null, cfg.TlsProtos, false); }
            catch (Exception ex)
            {
                tlsMs = -1;
                mode = "TLS 失败";
                remark = "TCP 通了但 TLS 握手失败（" + Short(ex) + "），典型的链路拦截 / 中间设备重置";
                if (h.Port != 443) remark += "；该端口不是 443，若它不是 HTTPS 服务（如 SSH），请改成 tcp/" + h.Host + ":" + h.Port;
                try { ssl.Close(); } catch { }
                return false;
            }

            tlsMs = sw.ElapsedMilliseconds;

            byte[] req = Encoding.ASCII.GetBytes(
                "GET / HTTP/1.1\r\nHost: " + h.Host + "\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) QuickerPing\r\nAccept: */*\r\nConnection: close\r\n\r\n");
            ssl.Write(req, 0, req.Length);
            ssl.Flush();
            string status = ReadLine(ssl);
            httpMs = sw.ElapsedMilliseconds;
            if (status.StartsWith("HTTP/") && status.Length >= 12)
            {
                mode = "HTTPS " + status.Substring(9, 3);
                string tail = status.Length > 13 ? status.Substring(13).Trim() : "";
                remark += (tail.Length > 0 ? tail : "可访问");
                try { ssl.Close(); } catch { }
                return true;
            }
            mode = "HTTP 无响应";
            remark = "TLS 通了但没返回 HTTP 状态行";
            try { ssl.Close(); } catch { }
            return false;
        }
        catch (Exception ex)
        {
            mode = "异常";
            remark = Short(ex);
            return false;
        }
    }

    private static string Short(Exception ex)
    {
        Exception e = ex;
        while (e.InnerException != null) e = e.InnerException;
        string m = e.Message;
        if (m.Length > 90) m = m.Substring(0, 90) + "…";
        return e.GetType().Name + ": " + m;
    }

    public static Result Probe(HostItem h, Config cfg)
    {
        Result r = new Result();
        r.Target = h;

        for (int i = 0; cfg.IcmpEnabled && i < cfg.Tries; i++)
        {
            r.Sent++;
            long ms; string ip;
            if (PingOnce(h.Host, cfg.PingTimeoutMs, out ms, out ip))
            {
                r.Recv++;
                if (r.IcmpMs < 0 || ms < r.IcmpMs) r.IcmpMs = ms;
            }
        }

        RunHttp(h, cfg, r);

        // TLS 失败重试：① 同一套协议重连一次（"远程方已关闭传输流"这类瞬时失败很常见）
        //              ② 仍失败则换"系统默认协议"（含 TLS1.3）再试
        if (!r.Ok && r.Mode == "TLS 失败")
        {
            SslProtocols[] ladder = new SslProtocols[] { cfg.TlsProtos, SslProtocols.None };
            for (int a = 0; a < ladder.Length; a++)
            {
                if (ladder[a] == cfg.TlsProtos && a == 0)
                {
                    // 第一轮：同协议重连
                }
                Config alt = new Config();
                alt.Hosts = cfg.Hosts;
                alt.PingTimeoutMs = cfg.PingTimeoutMs;
                alt.HttpTimeoutMs = cfg.HttpTimeoutMs;
                alt.Tries = cfg.Tries;
                alt.IcmpEnabled = cfg.IcmpEnabled;
                alt.Proxy = cfg.Proxy;
                alt.Resolved = cfg.Resolved;
                alt.ProxyNote = cfg.ProxyNote;
                alt.TlsProtos = ladder[a];

                Result r2 = new Result();
                r2.Target = h;
                r2.IcmpMs = r.IcmpMs;
                r2.Sent = r.Sent;
                r2.Recv = r.Recv;
                RunHttp(h, alt, r2);
                if (r2.Ok) return r2;
                if (r2.Mode != "TLS 失败") break;
            }
        }

        if (!r.Ok && (r.Mode == "TLS 失败" || r.Mode == "TCP 失败" || r.Mode == "HTTP 无响应"))
        {
            string icmp = (r.IcmpMs >= 0) ? ("ICMP 有回包 " + r.IcmpMs + " ms") : "ICMP 也无回包";
            r.Remark = r.Remark + "；" + icmp;
        }
        return r;
    }

    public static Color TierColor(Result r)
    {
        if (!r.Ok) return Color.FromArgb(203, 45, 45);
        if (r.HttpMs <= 200) return Color.FromArgb(34, 153, 84);
        if (r.HttpMs <= 500) return Color.FromArgb(41, 128, 185);
        if (r.HttpMs <= 1000) return Color.FromArgb(191, 143, 0);
        return Color.FromArgb(211, 84, 0);
    }

    public static string Report(List<Result> rs, long totalMs, string proxyNote)
    {
        int ok = 0;
        foreach (Result r in rs) if (r != null && r.Ok) ok++;

        StringBuilder sb = new StringBuilder();
        sb.AppendLine("网络连通性检测 v4    " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "    代理：" + proxyNote);
        sb.AppendLine("--------------------------------------------------------------");
        foreach (Result r in rs)
        {
            if (r == null) continue;
            string icmp = (r.IcmpMs >= 0) ? (r.IcmpMs + " ms") : "--";
            string tcp = (r.TcpMs >= 0) ? (r.TcpMs + " ms") : "--";
            string tls = (r.TlsMs >= 0) ? (r.TlsMs + " ms") : "--";
            if (r.Ok)
                sb.AppendLine(string.Format("[√] {0,-18} 总 {1,-8} 连接 {2,-7} TLS {3,-7} ICMP {4,-7} {5}  {6}", r.Target.Label, r.HttpMs + " ms", tcp, tls, icmp, r.Mode, r.Ip));
            else
                sb.AppendLine(string.Format("[×] {0,-18} 打不开   连接 {1,-7} TLS {2,-7} ICMP {3,-7} {4}  {5}", r.Target.Label, tcp, tls, icmp, r.Mode, r.Remark));
        }
        sb.AppendLine("--------------------------------------------------------------");
        sb.AppendLine(string.Format("结果：{0}/{1} 可访问，{2} 个打不开，总耗时 {3:0.0} 秒。", ok, rs.Count, rs.Count - ok, totalMs / 1000.0));
        sb.AppendLine("判定：以能否完成 HTTPS 请求（拿到 HTTP 状态码）为准，ICMP 只作参考。");
        sb.AppendLine("配色：按 HTTPS 总耗时 绿 ≤200ms · 蓝 ≤500ms · 黄 ≤1000ms · 橙 >1000ms · 红 打不开");
        sb.AppendLine("说明：总 = HTTPS 全流程耗时（连接 + TLS + 首字节），这就是浏览器打开这个站点大概要等的时间；");
        sb.AppendLine("      走代理时「连接」是连本地代理的耗时，真实网络耗时体现在「总」和「TLS」上；ICMP 只是参考。");
        return sb.ToString();
    }
}

public class ProbeForm : Form
{
    private NetProbe.Config cfg;
    private Label lblHeader, lblSummary, lblPath, lblStatus;
    private ListView list;
    private Button btnCopy, btnRerun, btnEdit, btnClose;
    private ListViewItem[] rows;
    private long elapsedMs;
    public string ReportText = "";

    public ProbeForm(NetProbe.Config config)
    {
        cfg = config;
        this.Text = "网络连通性检测 v4";
        this.ClientSize = new Size(960, 500);
        this.StartPosition = FormStartPosition.CenterScreen;
        this.Font = new Font("Microsoft YaHei UI", 9F);
        this.MinimizeBox = false;
        this.MaximizeBox = true;

        lblHeader = new Label();
        lblHeader.AutoSize = false;
        lblHeader.Location = new Point(14, 12);
        lblHeader.Size = new Size(930, 24);
        lblHeader.Font = new Font(this.Font.FontFamily, 11F, FontStyle.Bold);
        lblHeader.Text = "网络连通性检测";
        this.Controls.Add(lblHeader);

        lblSummary = new Label();
        lblSummary.AutoSize = false;
        lblSummary.Location = new Point(14, 38);
        lblSummary.Size = new Size(930, 22);
        lblSummary.Text = "准备中…";
        this.Controls.Add(lblSummary);

        lblPath = new Label();
        lblPath.AutoSize = false;
        lblPath.Location = new Point(14, 60);
        lblPath.Size = new Size(930, 18);
        lblPath.ForeColor = Color.FromArgb(120, 120, 120);
        lblPath.Text = "域名列表：" + NetProbe.ConfigPath();
        this.Controls.Add(lblPath);

        int lx = 14;
        int ly = 84;
        lx = AddLegend(lx, ly, "● ≤200ms 优秀", Color.FromArgb(34, 153, 84));
        lx = AddLegend(lx, ly, "● ≤500ms 良好", Color.FromArgb(41, 128, 185));
        lx = AddLegend(lx, ly, "● ≤1000ms 一般", Color.FromArgb(191, 143, 0));
        lx = AddLegend(lx, ly, "● >1000ms 较慢", Color.FromArgb(211, 84, 0));
        lx = AddLegend(lx, ly, "● 打不开", Color.FromArgb(203, 45, 45));

        list = new ListView();
        list.View = View.Details;
        list.FullRowSelect = true;
        list.HeaderStyle = ColumnHeaderStyle.Nonclickable;
        list.Location = new Point(14, 110);
        list.Size = new Size(932, 330);
        list.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        list.Columns.Add("状态", 64);
        list.Columns.Add("域名", 150);
        list.Columns.Add("HTTPS总", 80);
        list.Columns.Add("连接", 70);
        list.Columns.Add("TLS", 70);
        list.Columns.Add("ICMP", 70);
        list.Columns.Add("方式", 95);
        list.Columns.Add("IP 地址", 130);
        list.Columns.Add("备注", 203);
        list.DoubleClick += delegate(object s, EventArgs e)
        {
            if (list.SelectedItems.Count > 0)
                try { Clipboard.SetText(list.SelectedItems[0].SubItems[1].Text); lblStatus.Text = "已复制域名 " + list.SelectedItems[0].SubItems[1].Text; } catch { }
        };
        this.Controls.Add(list);

        lblStatus = new Label();
        lblStatus.AutoSize = false;
        lblStatus.Location = new Point(14, 450);
        lblStatus.Size = new Size(480, 24);
        lblStatus.ForeColor = Color.FromArgb(120, 120, 120);
        lblStatus.Text = "";
        lblStatus.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
        this.Controls.Add(lblStatus);

        btnEdit = new Button();
        btnEdit.Text = "编辑域名列表";
        btnEdit.Size = new Size(120, 28);
        btnEdit.Location = new Point(522, 448);
        btnEdit.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
        btnEdit.Click += delegate(object s, EventArgs e)
        {
            try { Process.Start("notepad.exe", NetProbe.ConfigPath()); }
            catch (Exception ex) { lblStatus.Text = "打开配置失败：" + ex.Message; }
        };
        this.Controls.Add(btnEdit);

        btnRerun = new Button();
        btnRerun.Text = "重新检测";
        btnRerun.Size = new Size(100, 28);
        btnRerun.Location = new Point(650, 448);
        btnRerun.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
        btnRerun.Click += delegate(object s, EventArgs e) { StartProbe(); };
        this.Controls.Add(btnRerun);

        btnCopy = new Button();
        btnCopy.Text = "复制结果";
        btnCopy.Size = new Size(100, 28);
        btnCopy.Location = new Point(758, 448);
        btnCopy.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
        btnCopy.Click += delegate(object s, EventArgs e)
        {
            try { Clipboard.SetText(ReportText); lblStatus.Text = "报告已复制到剪贴板"; }
            catch (Exception ex) { lblStatus.Text = "复制失败：" + ex.Message; }
        };
        this.Controls.Add(btnCopy);

        btnClose = new Button();
        btnClose.Text = "关闭";
        btnClose.Size = new Size(80, 28);
        btnClose.Location = new Point(866, 448);
        btnClose.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
        btnClose.Click += delegate(object s, EventArgs e) { this.Close(); };
        this.Controls.Add(btnClose);
    }

    private int AddLegend(int x, int y, string text, Color color)
    {
        Label l = new Label();
        l.AutoSize = true;
        l.Location = new Point(x, y);
        l.ForeColor = color;
        l.Font = new Font(this.Font, FontStyle.Bold);
        l.Text = text;
        this.Controls.Add(l);
        return x + TextRenderer.MeasureText(text, l.Font).Width + 22;
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        StartProbe();
    }

    private void StartProbe()
    {
        ReportText = "";
        btnRerun.Enabled = false;
        lblStatus.Text = "";
        lblSummary.ForeColor = Color.FromArgb(90, 90, 90);
        lblSummary.Text = "正在检测 " + cfg.Hosts.Count + " 个域名（HTTPS + ICMP）…";
        lblHeader.Text = "网络连通性检测    " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "    代理：解析中…";

        list.Items.Clear();
        rows = new ListViewItem[cfg.Hosts.Count];
        for (int i = 0; i < cfg.Hosts.Count; i++)
        {
            ListViewItem it = new ListViewItem(new string[] { "…", cfg.Hosts[i].Label, "", "", "", "", "", "", "" });
            it.ForeColor = Color.FromArgb(120, 120, 120);
            list.Items.Add(it);
            rows[i] = it;
        }

        Thread t = new Thread(delegate() { RunProbe(); });
        t.IsBackground = true;
        t.Start();
    }

    private void RunProbe()
    {
        NetProbe.ResolveProxy(cfg);
        try { this.BeginInvoke(new Action(delegate() { lblHeader.Text = "网络连通性检测    " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "    代理：" + cfg.ProxyNote; })); } catch { }

        List<NetProbe.Result> results = new List<NetProbe.Result>();
        for (int i = 0; i < cfg.Hosts.Count; i++) results.Add(null);

        int maxPar = Math.Max(1, Math.Min(6, cfg.Hosts.Count));
        Stopwatch sw = Stopwatch.StartNew();
        Parallel.For(0, cfg.Hosts.Count, new ParallelOptions { MaxDegreeOfParallelism = maxPar }, delegate(int i)
        {
            NetProbe.Result r = NetProbe.Probe(cfg.Hosts[i], cfg);
            results[i] = r;
            FillRow(i, r);
        });
        sw.Stop();
        elapsedMs = sw.ElapsedMilliseconds;
        Finish(results);
    }

    private void FillRow(int index, NetProbe.Result result)
    {
        int i = index;
        NetProbe.Result r = result;
        try { this.BeginInvoke(new Action(delegate() { FillRowUi(i, r); })); } catch { }
    }

    // 安全写单元格：列数变化时自动补 SubItem，避免 index 越界崩溃
    private void SetSub(ListViewItem it, int index, string text)
    {
        while (it.SubItems.Count <= index) it.SubItems.Add("");
        it.SubItems[index].Text = text;
    }

    private void FillRowUi(int i, NetProbe.Result r)
    {
        if (i < 0 || i >= rows.Length) return;

        ListViewItem it = rows[i];
        SetSub(it, 0, r.Ok ? "√ 可访问" : "× 打不开");
        SetSub(it, 2, r.Ok ? (r.HttpMs + " ms") : "--");
        SetSub(it, 3, (r.TcpMs >= 0) ? (r.TcpMs + " ms") : "--");
        SetSub(it, 4, (r.TlsMs >= 0) ? (r.TlsMs + " ms") : "--");
        SetSub(it, 5, (r.IcmpMs >= 0) ? (r.IcmpMs + " ms") : "--");
        SetSub(it, 6, r.Mode);
        SetSub(it, 7, r.Ip);
        SetSub(it, 8, r.Remark);
        it.ForeColor = NetProbe.TierColor(r);
    }

    private void Finish(List<NetProbe.Result> results)
    {
        List<NetProbe.Result> rs = results;
        try { this.BeginInvoke(new Action(delegate() { FinishUi(rs); })); } catch { }
    }

    private void FinishUi(List<NetProbe.Result> results)
    {
        int ok = 0;
        foreach (NetProbe.Result r in results) if (r != null && r.Ok) ok++;

        ReportText = NetProbe.Report(results, elapsedMs, cfg.ProxyNote);
        lblSummary.Text = string.Format("共 {0} 个域名：{1} 个可访问，{2} 个打不开，总耗时 {3:0.0} 秒。判定以 HTTPS 能否拿到响应为准，ICMP 仅参考。",
            results.Count, ok, results.Count - ok, elapsedMs / 1000.0);
        if (ok == results.Count) lblSummary.ForeColor = Color.FromArgb(34, 153, 84);
        else if (ok == 0) lblSummary.ForeColor = Color.FromArgb(203, 45, 45);
        else lblSummary.ForeColor = Color.FromArgb(191, 143, 0);
        btnRerun.Enabled = true;
        lblStatus.Text = "总 = HTTPS 全流程耗时；走代理时「连接」= 连本地代理耗时，真实耗时看「总」。双击行复制域名。";
    }
}


public static void Exec(Quicker.Public.IStepContext context)
{
    try
    {
        NetProbe.Config cfg = NetProbe.LoadConfig();

        ProbeForm[] box = new ProbeForm[1];
        Thread t = new Thread(delegate()
        {
            try
            {
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
            }
            catch { }

            ProbeForm f = new ProbeForm(cfg);
            box[0] = f;
            Application.Run(f);
        });
        t.SetApartmentState(ApartmentState.STA);
        t.Start();
        t.Join();

        string text = (box[0] == null) ? "" : box[0].ReportText;
        if (!string.IsNullOrEmpty(text)) context.SetVarValue("netResult", text);
    }
    catch (Exception ex)
    {
        MessageBox.Show("检测窗口启动失败：" + ex.Message, "网络连通性检测", MessageBoxButtons.OK, MessageBoxIcon.Warning);
    }
}
