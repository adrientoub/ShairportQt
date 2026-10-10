#include "airplay2/AirPlay2Handler.h"
#include "airplay2/Ap2AudioSession.h"
#include "airplay2/Ap2Decoder.h"
#include "airplay2/FairPlaySetup.h"
#include "airplay2/Pairing.h"
#include "airplay2/Plist.h"
#include "airplay2/PtpClock.h"
#include "sockpp/tcp_acceptor.h"
#include "sockpp/inet_address.h"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>

using namespace std;
using namespace string_literals;

namespace AirPlay2
{
    namespace
    {
        // features as used by shairport-sync for buffered audio without plist metadata
        // (bit 14, MFi soft FairPlay, is needed by iOS: it hangs up after the pairing without it):
        // bits 9, 11, 14, 18, 19, 20, 22, 30, 38, 40, 41, 47, 48
        constexpr uint64_t BaseFeatures = 0x00018340405C4A00ULL;
        constexpr uint64_t FeatureArtwork = 1ULL << 15;
        constexpr uint64_t FeatureProgress = 1ULL << 16;
        constexpr uint64_t FeatureText = 1ULL << 17;

        constexpr uint32_t StatusFlags = 0x4; // audio cable attached
        constexpr const char* Model = "ShairportQt";
        constexpr const char* OsVersion = "15.0";
        constexpr const char* FirmwareVersion = "p20.78100.3";

        // supported formats (see Ap2Decoder.cpp)
        constexpr uint64_t RealtimeFormats = 0x40000 | 0x400000;                        // ALAC/44.1k/16, AAC-LC/44.1k
        constexpr uint64_t BufferedFormats = 0x40000 | 0x200000 | 0x400000 | 0x800000; // + ALAC/48k/24, AAC-LC/48k

        const char* Hex = "0123456789abcdef";

        string ToHex(const Bytes& data, bool upper = false, const char* separator = "")
        {
            string result;

            for (size_t i = 0; i < data.size(); ++i)
            {
                if (i > 0)
                {
                    result += separator;
                }
                char c1 = Hex[data[i] >> 4];
                char c2 = Hex[data[i] & 0x0f];

                if (upper)
                {
                    c1 = static_cast<char>(toupper(c1));
                    c2 = static_cast<char>(toupper(c2));
                }
                result += c1;
                result += c2;
            }
            return result;
        }

        string CreateUuid()
        {
            auto b = Crypto::RandomBytes(16);
            b[6] = (b[6] & 0x0f) | 0x40;
            b[8] = (b[8] & 0x3f) | 0x80;
            const string h = ToHex(b, true);
            return h.substr(0, 8) + "-"s + h.substr(8, 4) + "-"s + h.substr(12, 4) + "-"s + h.substr(16, 4) + "-"s + h.substr(20, 12);
        }

        string Base64NoPad(const uint8_t* data, size_t len)
        {
            static const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            string out;
            size_t i = 0;

            for (; i + 2 < len; i += 3)
            {
                const uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) | data[i + 2];
                out += table[(v >> 18) & 63];
                out += table[(v >> 12) & 63];
                out += table[(v >> 6) & 63];
                out += table[v & 63];
            }
            if (i + 1 == len)
            {
                const uint32_t v = uint32_t(data[i]) << 16;
                out += table[(v >> 18) & 63];
                out += table[(v >> 12) & 63];
            }
            else if (i + 2 == len)
            {
                const uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8);
                out += table[(v >> 18) & 63];
                out += table[(v >> 12) & 63];
                out += table[(v >> 6) & 63];
            }
            return out;
        }

        string Hex32(uint64_t v)
        {
            char buf[16];
            snprintf(buf, sizeof(buf), "0x%X", static_cast<unsigned int>(v & 0xffffffffULL));
            return buf;
        }

        bool WaitReadable(const sockpp::socket& socket, int ms) noexcept
        {
            const auto handle = socket.handle();
            fd_set set;
            FD_ZERO(&set);
            FD_SET(handle, &set);
            timeval tv{ ms / 1000, (ms % 1000) * 1000 };
            return ::select(static_cast<int>(handle) + 1, &set, nullptr, nullptr, &tv) > 0;
        }

        bool IsPlistRequest(const Request& request)
        {
            auto contentType = request.Header("content-type");
            transform(contentType.begin(), contentType.end(), contentType.begin(), [](unsigned char c) { return static_cast<char>(tolower(c)); });
            return contentType.find("application/x-apple-binary-plist") != string::npos;
        }

        void SetPlist(Response& response, const Plist& plist)
        {
            const auto data = plist.ToBinary();
            response.body.assign(reinterpret_cast<const char*>(data.data()), data.size());
            response.contentType = "application/x-apple-binary-plist"s;
        }

        // RTSP path without the "rtsp://host/" prefix and the query
        string NormalizedPath(const string& path)
        {
            string result = path;
            const auto scheme = result.find("://");

            if (scheme != string::npos)
            {
                const auto slash = result.find('/', scheme + 3);
                result = slash == string::npos ? "/"s : result.substr(slash);
            }
            const auto query = result.find('?');

            if (query != string::npos)
            {
                result.resize(query);
            }
            return result;
        }
    }

    string Request::Header(const string& lowerCaseKey) const
    {
        const auto i = headers.find(lowerCaseKey);
        return i == headers.end() ? string{} : i->second;
    }

    EventChannel::EventChannel(sockpp::tcp_socket socket, const Bytes& secret, string remoteAddr)
        : m_socket(move(socket))
        // as an accessory we write with the "Events-Write" key and read with the "Events-Read" key
        // (unlike the control channel), so we use the controller's point of view
        , m_cipher(SecureChannel::ForEvents(secret, false))
        , m_remoteAddr(move(remoteAddr))
    {
    }

    string EventChannel::BuildCommandRequest(const Plist& command)
    {
        const auto body = command.ToBinary();

        string request = "POST /command RTSP/1.0\r\nContent-Length: "s + to_string(body.size()) +
            "\r\nContent-Type: application/x-apple-binary-plist\r\n\r\n"s;
        request.append(reinterpret_cast<const char*>(body.data()), body.size());
        return request;
    }

    int EventChannel::PostCommand(const Plist& command, int timeoutMs)
    {
        const lock_guard<mutex> guard(m_mtx);

        if (!m_open)
        {
            return -1;
        }
        const string request = BuildCommandRequest(command);
        string encrypted;
        m_cipher.Encrypt(reinterpret_cast<const uint8_t*>(request.data()), request.size(), encrypted);

        if (m_socket.write_n(encrypted.data(), encrypted.size()) != static_cast<ssize_t>(encrypted.size()))
        {
            spdlog::warn("AirPlay2: failed to write to the event channel");
            m_open = false;
            return -1;
        }
        // wait for the response
        const auto deadline = chrono::steady_clock::now() + chrono::milliseconds(timeoutMs);
        string response;
        uint8_t buffer[4096];

        for (;;)
        {
            const auto headerEnd = response.find("\r\n\r\n");

            if (headerEnd != string::npos)
            {
                string header = response.substr(0, headerEnd);
                transform(header.begin(), header.end(), header.begin(), [](unsigned char c) { return static_cast<char>(tolower(c)); });

                size_t contentLength = 0;
                const auto cl = header.find("content-length:");

                if (cl != string::npos)
                {
                    contentLength = strtoul(header.c_str() + cl + 15, nullptr, 10);
                }
                if (response.size() >= headerEnd + 4 + contentLength)
                {
                    break;
                }
            }
            const auto remaining = chrono::duration_cast<chrono::milliseconds>(deadline - chrono::steady_clock::now()).count();

            if (remaining <= 0)
            {
                spdlog::warn("AirPlay2: no response on the event channel");
                return -1;
            }
            if (!WaitReadable(m_socket, static_cast<int>(min<long long>(remaining, 100))))
            {
                continue;
            }
            const auto n = m_socket.read(buffer, sizeof(buffer));

            if (n <= 0 || !m_cipher.Decrypt(buffer, static_cast<size_t>(n), response))
            {
                spdlog::warn("AirPlay2: event channel closed while waiting for a response");
                m_open = false;
                return -1;
            }
        }
        // "RTSP/1.0 200 OK"
        if (response.size() < 12 || response.compare(0, 7, "RTSP/1.") != 0 || !isdigit(static_cast<unsigned char>(response[9])))
        {
            spdlog::warn("AirPlay2: invalid response on the event channel");
            return -1;
        }
        return atoi(response.c_str() + 9);
    }

    bool EventChannel::Poll()
    {
        const lock_guard<mutex> guard(m_mtx);

        if (!m_open)
        {
            return false;
        }
        if (!WaitReadable(m_socket, 0))
        {
            return true;
        }
        uint8_t buffer[4096];
        const auto n = m_socket.read(buffer, sizeof(buffer));

        if (n <= 0)
        {
            m_open = false;
            return false;
        }
        string plain;

        if (!m_cipher.Decrypt(buffer, static_cast<size_t>(n), plain))
        {
            spdlog::warn("AirPlay2: failed to decrypt the event channel");
            m_open = false;
            return false;
        }
        if (!plain.empty())
        {
            spdlog::debug("AirPlay2: unexpected data on the event channel: {}", plain.substr(0, plain.find('\r')));
        }
        return true;
    }

    void EventChannel::Close() noexcept
    {
        const lock_guard<mutex> guard(m_mtx);

        if (m_open)
        {
            m_open = false;
            m_socket.shutdown();
        }
        m_socket.close();
    }

    Connection::Connection(const Crypto::Ed25519Key& identity, const string& deviceId)
        : m_pairing(make_unique<Pairing>(identity, deviceId))
    {
    }

    Connection::~Connection()
    {
        StopEventChannel();
    }

    bool Connection::TakeEncryptionSecret(Bytes& secret)
    {
        return m_pairing->TakeEncryptionSecret(secret);
    }

    void Connection::StopEventChannel() noexcept
    {
        m_eventStop = true;

        if (m_eventThread.joinable())
        {
            m_eventThread.join();
        }
        if (m_eventAcceptor)
        {
            m_eventAcceptor->close();
            m_eventAcceptor.reset();
        }
        m_eventStop = false;
    }

    Service::Service(SharedPtr<IValueCollection> config, IHost* host)
        : m_config(move(config))
        , m_host(host)
        , m_remote(make_shared<RemoteState>())
    {
        m_remote->host = host;

        // persistent identity
        const auto key = VariantValue::Key("AirPlay2Key").TryGet<vector<uint8_t>>(m_config);

        if (key.has_value() && key->size() == 32)
        {
            m_identity = Crypto::Ed25519Key::FromPrivate(*key);
        }
        if (!m_identity.IsValid())
        {
            m_identity = Crypto::Ed25519Key::Generate();

            auto blob = MakeShared<BlobStream>();
            const auto& priv = m_identity.PrivateKey();
            blob->Write(priv.data(), static_cast<ULONG>(priv.size()), nullptr);
            VariantValue::Key("AirPlay2Key").Set(m_config, blob);
        }
        auto pi = VariantValue::Key("AirPlay2Pi").TryGet<string>(m_config);

        if (!pi.has_value() || pi->size() != 36)
        {
            pi = CreateUuid();
            VariantValue::Key("AirPlay2Pi").Set(m_config, *pi);
        }
        m_pi = *pi;

        auto psi = VariantValue::Key("AirPlay2Psi").TryGet<string>(m_config);

        if (!psi.has_value() || psi->size() != 36)
        {
            psi = CreateUuid();
            VariantValue::Key("AirPlay2Psi").Set(m_config, *psi);
        }
        m_psi = *psi;

        const auto hwAddr = VariantValue::Key("HWaddress").Get<vector<uint8_t>>(m_config);
        m_deviceId = ToHex(hwAddr, true, ":");
    }

    Service::~Service()
    {
        const lock_guard<mutex> guard(m_remote->mtx);
        m_remote->host = nullptr;
    }

    int Service::MediaRemoteCommand(const string& dacpCommand) noexcept
    {
        // MRMediaRemoteCommand
        if (dacpCommand == "play")
        {
            return 0;
        }
        if (dacpCommand == "pause")
        {
            return 1;
        }
        if (dacpCommand == "playpause")
        {
            return 2;
        }
        if (dacpCommand == "stop")
        {
            return 3;
        }
        if (dacpCommand == "nextitem")
        {
            return 4;
        }
        if (dacpCommand == "previtem")
        {
            return 5;
        }
        return -1;
    }

    bool Service::HasRemoteControl() const
    {
        const lock_guard<mutex> guard(m_remote->mtx);
        return !m_remote->channel.expired();
    }

    bool Service::SendRemoteCommand(const string& dacpCommand)
    {
        const int command = MediaRemoteCommand(dacpCommand);

        if (command < 0)
        {
            return false;
        }
        shared_ptr<EventChannel> channel;
        {
            const lock_guard<mutex> guard(m_remote->mtx);
            channel = m_remote->channel.lock();
        }
        if (!channel)
        {
            spdlog::info("AirPlay2: no event channel to send \"{}\"", dacpCommand);
            return false;
        }
        auto plist = Plist::Dict();
        plist.Set("type", Plist::String("sendMediaRemoteCommand"));
        plist.Set("modernMediaRemoteCommand", Plist::UInteger(static_cast<uint64_t>(command)));

        const int status = channel->PostCommand(plist);
        spdlog::debug("AirPlay2: sent MediaRemote command {} (\"{}\") to {}: status {}", command, dacpCommand, channel->RemoteAddr(), status);

        return status >= 200 && status < 300;
    }

    bool Service::IsSupported() noexcept
    {
        return Ap2Decoder::IsAvailable();
    }

    bool Service::IsEnabled() const
    {
        if (!IsSupported())
        {
            return false;
        }
        const auto enabled = VariantValue::Key("EnableAirPlay2").TryGet<bool>(m_config);

        if (!enabled.has_value() || !enabled.value())
        {
            return false;
        }
        // password protection is only supported with AirPlay 1
        const bool hasPassword = VariantValue::Key("HasPassword").TryGet<bool>(m_config).value_or(false) &&
            !VariantValue::Key("Password").TryGet<string>(m_config).value_or(string{}).empty();

        return !hasPassword;
    }

    uint64_t Service::Features() const
    {
        uint64_t features = BaseFeatures;
        const bool noMetaInfo = VariantValue::Key("NoMetaInfo").TryGet<bool>(m_config).value_or(false);

        if (!noMetaInfo)
        {
            features |= FeatureArtwork | FeatureProgress | FeatureText;
        }
        return features;
    }

    string Service::PublicKeyHex() const
    {
        return ToHex(m_identity.PublicKey());
    }

    TxtRecords Service::AirPlayTxtRecords() const
    {
        const uint64_t features = Features();
        uint8_t fex[8];

        for (int i = 0; i < 8; ++i)
        {
            fex[i] = static_cast<uint8_t>(features >> (8 * i));
        }
        char flags[16];
        snprintf(flags, sizeof(flags), "0x%X", StatusFlags);

        TxtRecords records;

        records.emplace_back("acl", "0");
        records.emplace_back("btaddr", "00:00:00:00:00:00");
        records.emplace_back("deviceid", m_deviceId);
        records.emplace_back("fex", Base64NoPad(fex, sizeof(fex)));
        records.emplace_back("features", Hex32(features) + ","s + Hex32(features >> 32));
        records.emplace_back("rsf", "0x0");
        records.emplace_back("flags", flags);
        records.emplace_back("gid", m_pi);
        records.emplace_back("igl", "0");
        records.emplace_back("gcgl", "0");
        records.emplace_back("model", Model);
        records.emplace_back("protovers", "1.1");
        records.emplace_back("pi", m_pi);
        records.emplace_back("psi", m_psi);
        records.emplace_back("pk", PublicKeyHex());
        records.emplace_back("srcvers", SourceVersion);
        records.emplace_back("osvers", OsVersion);
        records.emplace_back("vv", "2");
        records.emplace_back("fv", FirmwareVersion);

        return records;
    }

    TxtRecords Service::RaopTxtRecords() const
    {
        const uint64_t features = Features();
        char flags[16];
        snprintf(flags, sizeof(flags), "0x%X", StatusFlags);

        TxtRecords records;

        records.emplace_back("ft", Hex32(features) + ","s + Hex32(features >> 32));
        records.emplace_back("sf", flags);
        records.emplace_back("am", Model);
        records.emplace_back("pk", PublicKeyHex());
        records.emplace_back("vn", "65537");
        records.emplace_back("vs", SourceVersion);
        records.emplace_back("ov", OsVersion);
        records.emplace_back("fv", FirmwareVersion);

        return records;
    }

    shared_ptr<Connection> Service::CreateConnection() const
    {
        return make_shared<Connection>(m_identity, m_deviceId);
    }

    bool Service::IsAirPlay2Request(const Connection& connection, const Request& request) const
    {
        const string& m = request.method;

        if (m == "SETRATEANCHORTIME" || m == "FLUSHBUFFERED" || m == "SETPEERS" || m == "SETPEERSX" || m == "SETRATE")
        {
            return true;
        }
        if (m == "GET" || m == "POST")
        {
            const auto path = NormalizedPath(request.path);

            return path == "/info" || path == "/pair-setup" || path == "/pair-verify" || path == "/fp-setup"
                || path == "/feedback" || path == "/command" || path == "/audioMode" || path == "/configure"
                || path == "/pair-add" || path == "/pair-remove" || path == "/pair-list";
        }
        if (m == "SETUP")
        {
            return IsPlistRequest(request);
        }
        if (m == "RECORD" || m == "TEARDOWN")
        {
            return connection.IsAirPlay2();
        }
        return false;
    }

    bool Service::Handle(Connection& connection, const Request& request, Response& response)
    {
        if (!IsAirPlay2Request(connection, request))
        {
            return false;
        }
        const string& m = request.method;
        const auto path = NormalizedPath(request.path);

        spdlog::debug("AirPlay2: {} {}", m, path);

        // DACP remote control
        const auto dacpID = request.Header("dacp-id");
        const auto activeRemote = request.Header("active-remote");

        if (!dacpID.empty() && !activeRemote.empty() && m_host)
        {
            m_host->OnDacp(dacpID, activeRemote, request.remoteAddr);
        }
        response.headers.emplace_back("Server", "AirTunes/"s + SourceVersion);

        if (m == "GET" && path == "/info")
        {
            HandleInfo(request, response);
            return true;
        }
        connection.m_isAirPlay2 = true;

        if (m == "POST")
        {
            if (path == "/pair-setup" || path == "/pair-verify")
            {
                Bytes result;
                const auto* data = reinterpret_cast<const uint8_t*>(request.body.data());
                const bool ok = path == "/pair-setup"
                    ? connection.m_pairing->HandlePairSetup(data, request.body.size(), result)
                    : connection.m_pairing->HandlePairVerify(data, request.body.size(), result);

                if (!ok)
                {
                    spdlog::warn("AirPlay2: malformed {} request", path);
                    response.status = 400;
                    return true;
                }
                response.body.assign(reinterpret_cast<const char*>(result.data()), result.size());
                response.contentType = "application/octet-stream"s;
            }
            else if (path == "/fp-setup")
            {
                Bytes result;

                if (!HandleFairPlaySetup(reinterpret_cast<const uint8_t*>(request.body.data()), request.body.size(), result))
                {
                    response.status = 400;
                    return true;
                }
                response.body.assign(reinterpret_cast<const char*>(result.data()), result.size());
                response.contentType = "application/octet-stream"s;
            }
            else if (path == "/pair-add" || path == "/pair-remove" || path == "/pair-list")
            {
                // HomeKit pairing management is not supported
                spdlog::info("AirPlay2: unsupported request {}", path);
                response.status = 501;
            }
            else
            {
                // /feedback, /command, /audioMode, /configure
                if (path == "/command")
                {
                    Plist command;

                    if (Plist::FromBinary(request.body, command) && command.IsDict())
                    {
                        spdlog::debug("AirPlay2: sender command \"{}\"", command.Get("type").AsString());
                    }
                }
                response.status = 200;
            }
            return true;
        }
        if (m == "SETUP")
        {
            HandleSetup(connection, request, response);
        }
        else if (m == "RECORD")
        {
            response.headers.emplace_back("Audio-Latency", "0");
        }
        else if (m == "TEARDOWN")
        {
            HandleTeardown(connection, request, response);
        }
        else if (m == "SETRATEANCHORTIME")
        {
            HandleSetRateAnchorTime(connection, request, response);
        }
        else if (m == "FLUSHBUFFERED")
        {
            HandleFlushBuffered(connection, request, response);
        }
        else if (m == "SETRATE")
        {
            response.status = 501;
        }
        // SETPEERS(X): we only listen passively to the PTP master, nothing to do
        return true;
    }

    void Service::OnConnectionClosed(Connection& connection)
    {
        EndSession(connection);
        connection.StopEventChannel();
    }

    void Service::HandleInfo(const Request& request, Response& response) const
    {
        const uint64_t features = Features();
        uint8_t fex[8];

        for (int i = 0; i < 8; ++i)
        {
            fex[i] = static_cast<uint8_t>(features >> (8 * i));
        }
        const auto savedVolume = VariantValue::Key("Volume").TryGet<double>(m_config);
        const double volume = savedVolume.value_or(-15000.) / 1000.;

        spdlog::info("Volume: AirPlay 2 /info for {}: saved volume {}, advertising initialVolume {} dB",
            request.remoteAddr, savedVolume.has_value() ? to_string(savedVolume.value() / 1000.) + " dB"s : "unreadable (using default)"s,
            max(-30., min(0., volume)));

        auto info = Plist::Dict();

        info.Set("vv", Plist::Integer(2));
        info.Set("protocolVersion", Plist::String("1.1"));
        info.Set("volumeControlType", Plist::Integer(3));
        info.Set("canRecordScreenStream", Plist::Bool(false));
        info.Set("keepAliveSendStatsAsBody", Plist::Bool(false));
        info.Set("screenDemoMode", Plist::Bool(false));
        info.Set("receiverHDRCapability", Plist::String("4k60"));

        auto playback = Plist::Dict();
        playback.Set("supportsInterstitials", Plist::Bool(false));
        playback.Set("supportsFPSSecureStop", Plist::Bool(false));
        playback.Set("supportsUIForAudioOnlyContent", Plist::Bool(false));
        info.Set("playbackCapabilities", move(playback));

        info.Set("features", Plist::UInteger(features));
        info.Set("featuresEx", Plist::String(Base64NoPad(fex, sizeof(fex))));
        info.Set("statusFlags", Plist::UInteger(StatusFlags));
        info.Set("deviceID", Plist::String(m_deviceId));
        info.Set("pi", Plist::String(m_pi));
        info.Set("psi", Plist::String(m_psi));
        info.Set("name", Plist::String(VariantValue::Key("APname").Get<string>(m_config)));
        info.Set("model", Plist::String(Model));
        info.Set("pk", Plist::Data(m_identity.PublicKey()));
        info.Set("sourceVersion", Plist::String(SourceVersion));
        info.Set("initialVolume", Plist::Real(max(-30., min(0., volume))));
        info.Set("senderAddress", Plist::String(request.remoteAddr));

        auto formats = Plist::Dict();
        formats.Set("audioStream", Plist::UInteger(RealtimeFormats));
        formats.Set("bufferStream", Plist::UInteger(BufferedFormats));
        info.Set("supportedFormats", move(formats));

        // the TXT records of the _airplay._tcp service
        Bytes txt;

        for (const auto& record : AirPlayTxtRecords())
        {
            const string entry = record.first + "="s + record.second;
            txt.push_back(static_cast<uint8_t>(min<size_t>(entry.size(), 255)));
            txt.insert(txt.end(), entry.begin(), entry.begin() + min<size_t>(entry.size(), 255));
        }
        info.Set("txtAirPlay", Plist::Data(move(txt)));

        SetPlist(response, info);
    }

    shared_ptr<PtpClock> Service::GetClock()
    {
        lock_guard<mutex> guard(m_mtxClock);

        if (!m_clock)
        {
            m_clock = make_shared<PtpClock>();
        }
        return m_clock;
    }

    void Service::StartEventChannel(Connection& connection, const string& remoteAddr)
    {
        connection.StopEventChannel();

        auto acceptor = make_unique<sockpp::tcp_acceptor>();

        if (!acceptor->open(sockpp::inet_address(static_cast<in_port_t>(0))))
        {
            throw runtime_error("failed to open event port");
        }
        connection.m_eventAcceptor = move(acceptor);

        Connection* conn = &connection;
        const Bytes secret = connection.m_pairing->SharedSecret();

        connection.m_eventThread = thread([conn, remote = m_remote, secret, remoteAddr]()
            {
                // the event channel is used to send commands to the client (remote control)
                shared_ptr<EventChannel> channel;

                const auto release = [&channel, &remote]()
                    {
                        if (!channel)
                        {
                            return;
                        }
                        channel->Close();

                        const lock_guard<mutex> guard(remote->mtx);

                        if (remote->channel.lock() == channel)
                        {
                            remote->channel.reset();

                            if (remote->host)
                            {
                                remote->host->OnRemoteControl(channel->RemoteAddr(), false);
                            }
                        }
                        channel.reset();
                    };

                while (!conn->m_eventStop)
                {
                    try
                    {
                        if (WaitReadable(*conn->m_eventAcceptor, 100))
                        {
                            auto socket = conn->m_eventAcceptor->accept();

                            if (socket)
                            {
                                release();

                                if (secret.empty())
                                {
                                    spdlog::warn("AirPlay2: event channel connected without pairing, remote control is not available");
                                    socket.close();
                                    continue;
                                }
                                spdlog::debug("AirPlay2: event channel connected, remote control of {} is available", remoteAddr);
                                channel = make_shared<EventChannel>(move(socket), secret, remoteAddr);

                                const lock_guard<mutex> guard(remote->mtx);
                                remote->channel = channel;

                                if (remote->host)
                                {
                                    remote->host->OnRemoteControl(remoteAddr, true);
                                }
                            }
                        }
                        if (channel && !channel->Poll())
                        {
                            spdlog::debug("AirPlay2: event channel closed");
                            release();
                        }
                    }
                    catch (const exception& e)
                    {
                        spdlog::error("AirPlay2: event channel: {}", e.what());
                        break;
                    }
                }
                release();
            });
    }

    void Service::HandleSetup(Connection& connection, const Request& request, Response& response)
    {
        Plist setup;

        if (!Plist::FromBinary(request.body, setup) || !setup.IsDict())
        {
            spdlog::error("AirPlay2: SETUP without valid plist");
            response.status = 400;
            return;
        }
        const auto& streams = setup.Get("streams");

        if (streams.IsArray() && streams.Size() > 0)
        {
            HandleSetupStream(connection, request, streams[0], response);
            return;
        }
        // phase 1: timing and event channel
        const auto& timingProtocol = setup.Get("timingProtocol").AsString();

        if (!timingProtocol.empty() && timingProtocol != "PTP")
        {
            spdlog::warn("AirPlay2: unsupported timing protocol \"{}\"", timingProtocol);
        }
        auto clock = GetClock();

        if (!clock->IsListening())
        {
            spdlog::warn("AirPlay2: PTP ports 319/320 are not available, playback will not be synchronized");
        }
        try
        {
            StartEventChannel(connection, request.remoteAddr);
        }
        catch (const exception& e)
        {
            spdlog::error("AirPlay2: {}", e.what());
            response.status = 500;
            return;
        }
        const uint16_t eventPort = sockpp::inet_address(connection.m_eventAcceptor->address()).port();

        auto addresses = Plist::Array();
        addresses.Append(Plist::String(request.localAddr));

        auto timingPeerInfo = Plist::Dict();
        timingPeerInfo.Set("Addresses", move(addresses));
        timingPeerInfo.Set("ID", Plist::String(request.localAddr));

        auto result = Plist::Dict();
        result.Set("eventPort", Plist::UInteger(eventPort));
        result.Set("timingPort", Plist::UInteger(0));
        result.Set("timingPeerInfo", move(timingPeerInfo));

        SetPlist(response, result);
    }

    void Service::HandleSetupStream(Connection& connection, const Request& request, const Plist& stream, Response& response)
    {
        Ap2SessionParams params;

        const int type = static_cast<int>(stream.Get("type").AsInt());

        if (type != static_cast<int>(StreamType::Buffered) && type != static_cast<int>(StreamType::Realtime))
        {
            spdlog::error("AirPlay2: unsupported stream type {}", type);
            response.status = 501;
            return;
        }
        params.type = static_cast<StreamType>(type);
        params.sharedKey = stream.Get("shk").AsData();
        params.clientID = request.remoteAddr;

        if (params.sharedKey.size() != 32)
        {
            spdlog::error("AirPlay2: SETUP without valid shared key");
            response.status = 400;
            return;
        }
        if (!AudioFormatFromAirPlayFormat(stream.Get("audioFormat").AsUInt(), params.format))
        {
            // fall back to the compression type
            const auto ct = stream.Get("ct").AsInt();

            if (ct == 2)
            {
                params.format.codec = AudioCodec::ALAC;
            }
            else if (ct == 4)
            {
                params.format.codec = AudioCodec::AAC;
            }
            else
            {
                spdlog::error("AirPlay2: unsupported audio format (ct={}, audioFormat=0x{:x})", ct, stream.Get("audioFormat").AsUInt());
                response.status = 501;
                return;
            }
            params.format.sampleRate = static_cast<int>(stream.Get("sr").AsInt(44100));
            params.format.framesPerPacket = static_cast<int>(stream.Get("spf").AsInt(params.format.codec == AudioCodec::ALAC ? 352 : 1024));
        }
        else if (stream.Has("spf"))
        {
            params.format.framesPerPacket = static_cast<int>(stream.Get("spf").AsInt(params.format.framesPerPacket));
        }
        if ((params.format.sampleRate != 44100 && params.format.sampleRate != 48000) ||
            params.format.framesPerPacket <= 0 || params.format.framesPerPacket > 8192)
        {
            spdlog::error("AirPlay2: unsupported stream parameters (sr={}, spf={})", params.format.sampleRate, params.format.framesPerPacket);
            response.status = 501;
            return;
        }
        EndSession(connection);

        shared_ptr<Ap2AudioSession> session;

        try
        {
            session = make_shared<Ap2AudioSession>(m_config, params, GetClock());
        }
        catch (const exception& e)
        {
            spdlog::error("AirPlay2: failed to create audio session: {}", e.what());
            response.status = 500;
            return;
        }
        connection.m_session = session;

        if (m_host)
        {
            m_host->OnSessionStarted(session);
        }
        auto streamResult = Plist::Dict();
        streamResult.Set("type", Plist::Integer(type));
        streamResult.Set("dataPort", Plist::UInteger(session->GetDataPort()));
        streamResult.Set("controlPort", Plist::UInteger(session->GetControlPort()));

        if (params.type == StreamType::Buffered)
        {
            streamResult.Set("audioBufferSize", Plist::UInteger(Ap2AudioSession::AudioBufferSize));
        }
        auto streams = Plist::Array();
        streams.Append(move(streamResult));

        auto result = Plist::Dict();
        result.Set("streams", move(streams));

        spdlog::info("AirPlay2: {} stream set up ({}, {} Hz) for {}", params.type == StreamType::Buffered ? "buffered" : "realtime",
            params.format.codec == AudioCodec::ALAC ? "ALAC" : "AAC", params.format.sampleRate, request.remoteAddr);

        SetPlist(response, result);
    }

    void Service::EndSession(Connection& connection)
    {
        auto session = move(connection.m_session);
        connection.m_session.reset();

        if (session)
        {
            session->Stop();

            if (m_host)
            {
                m_host->OnSessionEnded(session);
            }
        }
    }

    void Service::HandleTeardown(Connection& connection, const Request& request, Response&)
    {
        Plist teardown;

        if (Plist::FromBinary(request.body, teardown) && teardown.IsDict() && teardown.Has("streams"))
        {
            // only the stream is removed, the connection stays in place
            EndSession(connection);
            return;
        }
        EndSession(connection);
        connection.StopEventChannel();
    }

    void Service::HandleSetRateAnchorTime(Connection& connection, const Request& request, Response& response)
    {
        Plist anchor;

        if (!Plist::FromBinary(request.body, anchor) || !anchor.IsDict())
        {
            response.status = 400;
            return;
        }
        if (!connection.m_session)
        {
            response.status = 455; // method not valid in this state
            return;
        }
        const double rate = anchor.Get("rate").AsReal(static_cast<double>(anchor.Get("rate").AsInt(0)));

        optional<uint32_t> rtpTime;
        optional<int64_t> networkTimeNs;
        uint64_t clockId = 0;

        if (anchor.Has("rtpTime"))
        {
            rtpTime = static_cast<uint32_t>(anchor.Get("rtpTime").AsUInt());
        }
        if (anchor.Has("networkTimeSecs"))
        {
            const uint64_t secs = anchor.Get("networkTimeSecs").AsUInt();
            const uint64_t frac = anchor.Get("networkTimeFrac").AsUInt();
            networkTimeNs = static_cast<int64_t>(secs * 1'000'000'000ULL + (((frac >> 32) * 1'000'000'000ULL) >> 32));
            clockId = anchor.Get("networkTimeTimelineID").AsUInt();
        }
        connection.m_session->SetRateAnchor(rate, rtpTime, networkTimeNs, clockId);
    }

    void Service::HandleFlushBuffered(Connection& connection, const Request& request, Response& response)
    {
        Plist flush;

        if (!Plist::FromBinary(request.body, flush) || !flush.IsDict())
        {
            response.status = 400;
            return;
        }
        if (!connection.m_session)
        {
            return;
        }
        FlushRequest flushRequest;

        const auto get = [&flush](const char* key) -> optional<uint32_t>
            {
                if (flush.Has(key))
                {
                    return static_cast<uint32_t>(flush.Get(key).AsUInt());
                }
                return nullopt;
            };
        flushRequest.fromSeq = get("flushFromSeq");
        flushRequest.fromTimestamp = get("flushFromTS");
        flushRequest.untilSeq = get("flushUntilSeq");
        flushRequest.untilTimestamp = get("flushUntilTS").value_or(0);

        if (!flushRequest.fromSeq.has_value() && flushRequest.fromTimestamp.has_value())
        {
            spdlog::warn("AirPlay2: FLUSHBUFFERED with flushFromTS but without flushFromSeq");
        }
        connection.m_session->FlushBuffered(flushRequest);
    }
}
