#pragma once
// PSK Reporter IPFIX/UDP sender for SDR++ Brown FT8 decoder
// Protocol reference: https://pskreporter.info/pskdev.html
// Sends reception reports to report.pskreporter.info:4739

#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <random>
#include <utils/net.h>
#include <utils/flog.h>

// ──────────────────────────────────────────────────────────
// IPFIX helper: big-endian writers
// ──────────────────────────────────────────────────────────
namespace pskr_ipfix {

static void writeU8(std::vector<uint8_t>& buf, uint8_t v) {
    buf.push_back(v);
}

static void writeU16BE(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back((v >> 8) & 0xFF);
    buf.push_back(v & 0xFF);
}

static void writeU32BE(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back((v >> 24) & 0xFF);
    buf.push_back((v >> 16) & 0xFF);
    buf.push_back((v >>  8) & 0xFF);
    buf.push_back(v & 0xFF);
}

// IPFIX variable-length string field: 1 byte length + data (max 254 bytes)
static void writeVarStr(std::vector<uint8_t>& buf, const std::string& s) {
    size_t len = std::min(s.size(), (size_t)254);
    buf.push_back((uint8_t)len);
    buf.insert(buf.end(), s.begin(), s.begin() + len);
}

// Overwrite U16 big-endian at position pos in buf
static void patchU16BE(std::vector<uint8_t>& buf, size_t pos, uint16_t v) {
    buf[pos]   = (v >> 8) & 0xFF;
    buf[pos+1] = v & 0xFF;
}

// Pad buf to multiple of 4 bytes with zeros
static void padTo4(std::vector<uint8_t>& buf) {
    while (buf.size() % 4 != 0) buf.push_back(0);
}

// ──────────────────────────────────────────────────────────
// Template bytes (pre-built, from pskreporter spec)
//
// Receiver info template (ID 0x9992 = 39314):
//   fields: receiverCallsign(80 02), receiverLocator(80 04),
//           decoderSoftware(80 08), antennaInformation(80 09)
//   => 4 fields => template length 0x2C = 44
//   enterprise number 30351 = 0x00 0x00 0x76 0x8F
//
// Sender info template (ID 0x9993 = 39315), variant 0x0008:
//   fields: senderCallsign(80 01), frequency(80 05, 4b),
//           sNR(80 06, 1b), iMD(80 07, 1b), mode(80 0A),
//           informationSource(80 0B, 1b), senderLocator(80 03),
//           flowStartSeconds(00 96, 4b)
//   => 8 fields => template length 0x44 = 68
// ──────────────────────────────────────────────────────────

// Receiver template set (Set ID=3 means template set)
static const uint8_t RECEIVER_TEMPLATE[] = {
    // Set header: Set ID=3, length=44 (0x2C)
    0x00, 0x03, 0x00, 0x2C,
    // Template record: template ID=0x9992, field count=4
    0x99, 0x92, 0x00, 0x04, 0x00, 0x01,  // NOTE: 0x00 0x01 = scope field count = 1 (options template, but used as data here — actually this is NOT options template, it's the PSKREPORTER receiver record descriptor with scope=1)
    // Actually for regular receiver template the format per spec is:
    // 00 03 00 2C  99 92  00 04  00 01
    // field: receiverCallsign (enterprise, id=0x8002 -> 0x8002 means enterprise bit set, id=2)
    0x80, 0x02, 0xFF, 0xFF, 0x00, 0x00, 0x76, 0x8F,
    // field: receiverLocator
    0x80, 0x04, 0xFF, 0xFF, 0x00, 0x00, 0x76, 0x8F,
    // field: decoderSoftware
    0x80, 0x08, 0xFF, 0xFF, 0x00, 0x00, 0x76, 0x8F,
    // field: antennaInformation
    0x80, 0x09, 0xFF, 0xFF, 0x00, 0x00, 0x76, 0x8F,
    // end of template
    0x00, 0x00
};

// Sender template set
static const uint8_t SENDER_TEMPLATE[] = {
    // Set header: Set ID=2, length=68 (0x44)
    0x00, 0x02, 0x00, 0x44,
    // Template record: template ID=0x9993, field count=8
    0x99, 0x93, 0x00, 0x08,
    // field: senderCallsign (variable length, enterprise)
    0x80, 0x01, 0xFF, 0xFF, 0x00, 0x00, 0x76, 0x8F,
    // field: frequency (4 bytes fixed, enterprise)
    0x80, 0x05, 0x00, 0x04, 0x00, 0x00, 0x76, 0x8F,
    // field: sNR (1 byte, enterprise)
    0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x76, 0x8F,
    // field: iMD (1 byte, enterprise)
    0x80, 0x07, 0x00, 0x01, 0x00, 0x00, 0x76, 0x8F,
    // field: mode (variable length, enterprise)
    0x80, 0x0A, 0xFF, 0xFF, 0x00, 0x00, 0x76, 0x8F,
    // field: informationSource (1 byte, enterprise)
    0x80, 0x0B, 0x00, 0x01, 0x00, 0x00, 0x76, 0x8F,
    // field: senderLocator (variable length, enterprise)
    0x80, 0x03, 0xFF, 0xFF, 0x00, 0x00, 0x76, 0x8F,
    // field: flowStartSeconds (IETF id=150, 4 bytes)
    0x00, 0x96, 0x00, 0x04
};

} // namespace pskr_ipfix

// ──────────────────────────────────────────────────────────
// PSKReporter — main class
// ──────────────────────────────────────────────────────────
class PSKReporter {
public:
    struct Spot {
        std::string senderCallsign;
        std::string senderLocator;   // may be empty
        long long   frequencyHz;
        int8_t      snr;             // dB
        std::string mode;            // "FT8" or "FT4"
        uint32_t    flowStartSeconds;// unix timestamp
    };

    PSKReporter() {
        std::random_device rd;
        std::mt19937 rng(rd());
        sessionId_ = rng();
        seqNo_ = 0;
        templatesSentCount_ = 0;
        lastTemplateSentTime_ = 0;
        lastSendTime_ = 0;
        running_ = false;
    }

    ~PSKReporter() {
        stop();
    }

    // Call this when PSK Reporter is enabled/re-configured
    void start(const std::string& receiverCallsign,
               const std::string& receiverLocator,
               const std::string& decoderSoftware,
               const std::string& antennaInfo) {
        stop();
        receiverCallsign_ = receiverCallsign;
        receiverLocator_  = receiverLocator;
        decoderSoftware_  = decoderSoftware;
        antennaInfo_      = antennaInfo;
        running_ = true;
        sendThread_ = std::thread(&PSKReporter::sendLoop, this);
    }

    void stop() {
        running_ = false;
        cv_.notify_all();
        if (sendThread_.joinable()) {
            sendThread_.join();
        }
    }

    // Update receiver info (called on config change, does not restart thread)
    void setReceiverInfo(const std::string& callsign,
                         const std::string& locator,
                         const std::string& software,
                         const std::string& antenna) {
        std::lock_guard<std::mutex> lk(mtx_);
        receiverCallsign_ = callsign;
        receiverLocator_  = locator;
        decoderSoftware_  = software;
        antennaInfo_      = antenna;
    }

    // Add a spot. Thread-safe. Handles deduplication (5-min window per call+band).
    void addSpot(const Spot& spot) {
        if (spot.senderCallsign.empty()) return;
        std::lock_guard<std::mutex> lk(mtx_);
        auto key = makeDedupeKey(spot);
        auto now = (uint32_t)time(nullptr);
        // Remove expired dedup entries
        dedup_.erase(std::remove_if(dedup_.begin(), dedup_.end(), [now](const DedupeEntry& e){
            return now - e.lastSeen >= DEDUP_SECONDS;
        }), dedup_.end());
        // Check duplicate
        for (auto& e : dedup_) {
            if (e.key == key) {
                e.lastSeen = now;
                return;  // already queued/sent recently
            }
        }
        // New spot
        dedup_.push_back({key, now});
        queue_.push_back(spot);
        pendingSpots_ = (int)queue_.size();
    }

    int getPendingCount() const { return pendingSpots_.load(); }
    uint32_t getLastSendTime() const { return lastSendTime_.load(); }
    bool isRunning() const { return running_.load(); }

private:
    static constexpr int DEDUP_SECONDS = 5 * 60;
    static constexpr int SEND_INTERVAL_SECONDS = 5 * 60;
    static constexpr const char* PSKREPORTER_HOST = "report.pskreporter.info";
    static constexpr int PSKREPORTER_PORT = 4739;

    struct DedupeEntry {
        std::string key;
        uint32_t    lastSeen;
    };

    std::string makeDedupeKey(const Spot& s) {
        // Band is approximate: round frequency to MHz
        long long bandMHz = s.frequencyHz / 1000000LL;
        return s.senderCallsign + "|" + std::to_string(bandMHz);
    }

    // ──────────────────────────────────────────────────────
    // Background send loop
    // ──────────────────────────────────────────────────────
    void sendLoop() {
        // Randomize first send delay within [0, 30] seconds to avoid sync storms
        std::random_device rd;
        std::mt19937 rng(rd());
        std::uniform_int_distribution<int> jitter(0, 30);
        int firstDelay = jitter(rng);

        {
            std::unique_lock<std::mutex> lk(sleepMtx_);
            cv_.wait_for(lk, std::chrono::seconds(firstDelay), [this]{ return !running_.load(); });
        }

        while (running_) {
            trySend();

            // Sleep until next send interval (check running_ every second)
            int elapsed = 0;
            while (running_ && elapsed < SEND_INTERVAL_SECONDS) {
                std::unique_lock<std::mutex> lk(sleepMtx_);
                cv_.wait_for(lk, std::chrono::seconds(1), [this]{ return !running_.load(); });
                elapsed++;
            }
        }
    }

    void trySend() {
        std::vector<Spot> toSend;
        std::string callsign, locator, software, antenna;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            if (queue_.empty()) return;
            toSend = queue_;
            queue_.clear();
            pendingSpots_ = 0;
            callsign = receiverCallsign_;
            locator  = receiverLocator_;
            software = decoderSoftware_;
            antenna  = antennaInfo_;
        }
        if (callsign.empty()) {
            flog::warn("PSKReporter: no receiver callsign set, skipping send");
            return;
        }

        try {
            auto pkt = buildPacket(toSend, callsign, locator, software, antenna);
            if (pkt.empty()) return;
            net::Address laddr("0.0.0.0", 0);
            auto sock = net::openudp(PSKREPORTER_HOST, PSKREPORTER_PORT, laddr);
            sock->send(pkt.data(), pkt.size());
            sock->close();
            lastSendTime_ = (uint32_t)time(nullptr);
            flog::info("PSKReporter: sent {} spots ({} bytes)", (int)toSend.size(), (int)pkt.size());
        } catch (const std::exception& e) {
            flog::error("PSKReporter: send failed: {}", e.what());
        }
    }

    // ──────────────────────────────────────────────────────
    // Build IPFIX UDP packet
    // ──────────────────────────────────────────────────────
    std::vector<uint8_t> buildPacket(const std::vector<Spot>& spots,
                                      const std::string& rxCall,
                                      const std::string& rxLoc,
                                      const std::string& software,
                                      const std::string& antenna) {
        using namespace pskr_ipfix;
        std::vector<uint8_t> pkt;

        uint32_t now = (uint32_t)time(nullptr);
        bool sendTemplates = (templatesSentCount_ < 3) ||
                             (now - lastTemplateSentTime_ >= 3600);

        // ── IPFIX message header (16 bytes) ──────────────────
        // version=10 (0x000A), length (patched later),
        // exportTime, seqNo, observationDomainId=sessionId
        writeU16BE(pkt, 0x000A);
        size_t totalLenPos = pkt.size();
        writeU16BE(pkt, 0);             // total length placeholder
        writeU32BE(pkt, now);           // export time
        writeU32BE(pkt, seqNo_);        // sequence number
        writeU32BE(pkt, sessionId_);    // session/observation domain ID
        seqNo_ += (uint32_t)spots.size();

        // ── Templates (if needed) ─────────────────────────────
        if (sendTemplates) {
            // Receiver template
            pkt.insert(pkt.end(),
                       std::begin(RECEIVER_TEMPLATE),
                       std::end(RECEIVER_TEMPLATE));
            padTo4(pkt);
            // Sender template
            pkt.insert(pkt.end(),
                       std::begin(SENDER_TEMPLATE),
                       std::end(SENDER_TEMPLATE));
            padTo4(pkt);
            templatesSentCount_++;
            lastTemplateSentTime_ = now;
        }

        // ── Receiver information record (set ID = 0x9992) ────
        {
            size_t setStart = pkt.size();
            writeU16BE(pkt, 0x9992);    // set ID matches template
            size_t setLenPos = pkt.size();
            writeU16BE(pkt, 0);         // length placeholder

            writeVarStr(pkt, rxCall);
            writeVarStr(pkt, rxLoc);
            writeVarStr(pkt, software);
            writeVarStr(pkt, antenna);

            padTo4(pkt);
            // Patch set length
            patchU16BE(pkt, setLenPos, (uint16_t)(pkt.size() - setStart));
        }

        // ── Sender information records (set ID = 0x9993) ─────
        {
            size_t setStart = pkt.size();
            writeU16BE(pkt, 0x9993);    // set ID matches sender template
            size_t setLenPos = pkt.size();
            writeU16BE(pkt, 0);         // length placeholder

            for (const auto& s : spots) {
                writeVarStr(pkt, s.senderCallsign);
                writeU32BE(pkt, (uint32_t)s.frequencyHz);
                writeU8(pkt, (uint8_t)(int8_t)s.snr);
                writeU8(pkt, 0);         // iMD not available for FT8/FT4
                writeVarStr(pkt, s.mode);
                writeU8(pkt, 1);         // informationSource = 1 (automatically extracted)
                writeVarStr(pkt, s.senderLocator);
                writeU32BE(pkt, s.flowStartSeconds);
            }

            padTo4(pkt);
            patchU16BE(pkt, setLenPos, (uint16_t)(pkt.size() - setStart));
        }

        // Patch total message length
        patchU16BE(pkt, totalLenPos, (uint16_t)pkt.size());

        return pkt;
    }

    // State
    std::string receiverCallsign_;
    std::string receiverLocator_;
    std::string decoderSoftware_;
    std::string antennaInfo_;

    std::vector<Spot>        queue_;
    std::vector<DedupeEntry> dedup_;
    std::mutex               mtx_;

    std::thread              sendThread_;
    std::atomic<bool>        running_;
    std::mutex               sleepMtx_;
    std::condition_variable  cv_;

    uint32_t              sessionId_;
    std::atomic<uint32_t> seqNo_;
    int                   templatesSentCount_;
    uint32_t              lastTemplateSentTime_;
    std::atomic<uint32_t> lastSendTime_;
    std::atomic<int>      pendingSpots_;
};

// ──────────────────────────────────────────────────────────
// Utility: extract Maidenhead grid locator from FT8 message
// Returns empty string if not found.
// Valid: 2-char letters (A-R/a-r) + 2 digits + optional 2 letters (a-x/A-X)
// ──────────────────────────────────────────────────────────
inline std::string extractGridFromFT8Message(const std::string& msg) {
    // Tokenize
    std::string token;
    std::istringstream ss(msg);
    while (ss >> token) {
        auto len = token.size();
        // Full 6-char locator: AA00AA
        if (len == 6) {
            if (std::isalpha(token[0]) && std::isalpha(token[1]) &&
                std::isdigit(token[2]) && std::isdigit(token[3]) &&
                std::isalpha(token[4]) && std::isalpha(token[5])) {
                char c0 = std::toupper(token[0]);
                char c1 = std::toupper(token[1]);
                if (c0 >= 'A' && c0 <= 'R' && c1 >= 'A' && c1 <= 'R') {
                    return token.substr(0, 6);
                }
            }
        }
        // 4-char locator: AA00
        if (len == 4) {
            if (std::isalpha(token[0]) && std::isalpha(token[1]) &&
                std::isdigit(token[2]) && std::isdigit(token[3])) {
                char c0 = std::toupper(token[0]);
                char c1 = std::toupper(token[1]);
                if (c0 >= 'A' && c0 <= 'R' && c1 >= 'A' && c1 <= 'R') {
                    return token.substr(0, 4);
                }
            }
        }
    }
    return "";
}
