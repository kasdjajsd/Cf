// ============================================================================
// Modern Anti-AFK + AutoClick Detection DLL (C++17)
// Optimized with better detection, safety & stability
// ============================================================================
// Compile: cl. exe /O2 /EHsc AntiCheatDetector.cpp /LD
// ============================================================================

#include <windows.h>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <algorithm>
#include <cmath>
#include <mutex>
#include <memory>
#include <queue>
#include <string>

using namespace std::chrono;

// ============================== CONFIG ======================================
// IMPORTANT: Replace these addresses with your actual game addresses! 
#define ADDR_PACKET_HANDLER  0x00401234  // Address of packet handler function
#define ADDR_KICK_FUNC       0x00405678  // Address of kick player function
#define OP_FIRE              0x0A        // Opcode for fire/shoot packet

// Detection thresholds (tunable)
#define AFK_TIMEOUT_SEC      120         // 2 minutes AFK = kick
#define AUTOCLICK_MIN_SAMPLES 8          // Need 8+ samples to detect
#define AUTOCLICK_VAR_MAX     5. 0        // Max variance (ms) for autoclick
#define AUTOCLICK_AVG_MAX     100        // Max average interval (ms)
#define BURST_FIRE_COUNT      20         // Shots to trigger burst detection
#define BURST_FIRE_WINDOW_MS  500        // Time window for burst (ms)
#define CHECK_INTERVAL_MS     2000       // Checker thread interval
#define FLAGGED_CLEANUP_MS    100        // Wait before removing flagged player

// ===============================================================================

// Function pointers
typedef void(__stdcall* PacketHandler_t)(void* player, int sid, int opcode, void* data, int len);
typedef void(__stdcall* KickFunc_t)(void* player, int sid, const char* reason);

PacketHandler_t oPacketHandler = nullptr;
KickFunc_t KickPlayer = nullptr;

// ========================= PLAYER STATE MANAGER =============================

struct PlayerStats {
    steady_clock::time_point lastActive;
    steady_clock::time_point lastShoot;
    std::vector<double> shootIntervals;
    std::vector<steady_clock::time_point> shootTimes;
    int totalShots;
    bool flagged;
    
    PlayerStats() 
        : lastActive(steady_clock::now()), 
          lastShoot(steady_clock::now()),
          totalShots(0),
          flagged(false) 
    {
    }
};

class PlayerManager {
private:
    std::unordered_map<int, std::unique_ptr<PlayerStats>> players;
    mutable std::mutex lock;
    
    static constexpr size_t MAX_HISTORY = 15;
    static constexpr size_t BURST_HISTORY = 50;

public:
    PlayerManager() = default;
    ~PlayerManager() = default;

    // ========== Mark player as active (update AFK timer) ==========
    void MarkActive(int sid) {
        std::lock_guard<std::mutex> guard(lock);
        auto& player = players[sid];
        if (! player) {
            player = std::make_unique<PlayerStats>();
        }
        player->lastActive = steady_clock::now();
    }

    // ========== Log shoot time ==========
    void LogShoot(int sid) {
        std::lock_guard<std::mutex> guard(lock);
        auto& player = players[sid];
        if (! player) {
            player = std::make_unique<PlayerStats>();
        }
        
        auto now = steady_clock::now();
        
        // Calculate interval from last shot
        if (player->lastShoot.time_since_epoch().count() != 0) {
            double ms = duration_cast<milliseconds>(now - player->lastShoot).count();
            player->shootIntervals. push_back(ms);
            
            // Keep only last N intervals
            if (player->shootIntervals.size() > MAX_HISTORY) {
                player->shootIntervals.erase(player->shootIntervals. begin());
            }
        }
        
        // Track shoot times for burst detection
        player->shootTimes.push_back(now);
        if (player->shootTimes.size() > BURST_HISTORY) {
            player->shootTimes.erase(player->shootTimes.begin());
        }
        
        player->lastShoot = now;
        player->totalShots++;
    }

    // ========== Check if player is AutoClicking ==========
    bool IsAutoClick(int sid) {
        std::lock_guard<std::mutex> guard(lock);
        auto it = players.find(sid);
        if (it == players.end()) {
            return false;
        }

        auto& stats = *it->second;
        auto& v = stats.shootIntervals;
        
        // Need enough samples
        if (v.size() < AUTOCLICK_MIN_SAMPLES) {
            return false;
        }

        // ===== Check 1: Consistency Detection =====
        // Calculate average
        double sum = 0.0;
        for (double x : v) {
            sum += x;
        }
        double avg = sum / v.size();

        // Calculate standard deviation
        double var_sum = 0.0;
        for (double x : v) {
            var_sum += std::pow(x - avg, 2. 0);
        }
        double variance = std::sqrt(var_sum / v.size());

        bool isConsistent = (variance < AUTOCLICK_VAR_MAX) && (avg < AUTOCLICK_AVG_MAX);

        // ===== Check 2: Burst Fire Detection =====
        bool isBurst = CheckBurstFire(stats. shootTimes);

        return isConsistent || isBurst;
    }

    // ========== Check for burst fire (too many shots in short time) ==========
    bool CheckBurstFire(const std::vector<steady_clock::time_point>& times) {
        if (times.size() < BURST_FIRE_COUNT) {
            return false;
        }

        // Check if last N shots are within burst window
        auto earliest = times.back();
        for (auto it = times.rbegin(); it != times.rend(); ++it) {
            auto elapsed = duration_cast<milliseconds>(times.back() - *it). count();
            if (elapsed > BURST_FIRE_WINDOW_MS) {
                // Found a gap larger than window
                // Count shots after this point
                size_t count = std::distance(times.begin(), 
                                           std::find(times.begin(), times.end(), *it));
                return count >= BURST_FIRE_COUNT;
            }
        }

        // All shots are within window
        return times.size() >= BURST_FIRE_COUNT;
    }

    // ========== Check if player is AFK ==========
    bool IsAFK(int sid) {
        std::lock_guard<std::mutex> guard(lock);
        auto it = players.find(sid);
        if (it == players.end()) {
            return false;
        }

        auto elapsed = duration_cast<seconds>(steady_clock::now() - it->second->lastActive).count();
        return elapsed >= AFK_TIMEOUT_SEC;
    }

    // ========== Flag player (cooldown before removal) ==========
    void FlagPlayer(int sid) {
        std::lock_guard<std::mutex> guard(lock);
        auto it = players. find(sid);
        if (it != players.end()) {
            it->second->flagged = true;
        }
    }

    // ========== Check if player is flagged ==========
    bool IsFlagged(int sid) {
        std::lock_guard<std::mutex> guard(lock);
        auto it = players.find(sid);
        return it != players.end() && it->second->flagged;
    }

    // ========== Remove player data ==========
    void RemovePlayer(int sid) {
        std::lock_guard<std::mutex> guard(lock);
        players.erase(sid);
    }

    // ========== Get all active players ==========
    std::vector<int> GetAllPlayers() {
        std::lock_guard<std::mutex> guard(lock);
        std::vector<int> result;
        for (auto& p : players) {
            result. push_back(p.first);
        }
        return result;
    }

    // ========== Get player count ==========
    size_t GetPlayerCount() {
        std::lock_guard<std::mutex> guard(lock);
        return players.size();
    }

    // ========== Get player stats (for debugging) ==========
    void GetPlayerStats(int sid, int& shots, double& avg_interval) {
        std::lock_guard<std::mutex> guard(lock);
        auto it = players. find(sid);
        if (it == players.end()) {
            shots = 0;
            avg_interval = 0.0;
            return;
        }

        auto& stats = *it->second;
        shots = stats.totalShots;
        
        if (stats.shootIntervals.empty()) {
            avg_interval = 0.0;
        } else {
            double sum = 0.0;
            for (double x : stats. shootIntervals) {
                sum += x;
            }
            avg_interval = sum / stats. shootIntervals.size();
        }
    }
};

// Global player manager
PlayerManager g_playerMgr;

// ========================= HOOK FUNCTION =====================================

void __stdcall hkPacketHandler(void* player, int sid, int opcode, void* data, int len) {
    __try {
        // Mark player as active
        g_playerMgr.MarkActive(sid);

        // Log shoot if fire packet
        if (opcode == OP_FIRE && data != nullptr) {
            g_playerMgr.LogShoot(sid);
        }

        // Call original handler
        if (oPacketHandler) {
            oPacketHandler(player, sid, opcode, data, len);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        char buffer[256];
        sprintf_s(buffer, sizeof(buffer), 
                 "[AC_ERROR] Exception in hkPacketHandler (sid=%d, opcode=%d)\n", 
                 sid, opcode);
        OutputDebugStringA(buffer);
    }
}

// ========================= DETECTION WORKER THREAD ============================

DWORD WINAPI CheckerThread(LPVOID) {
    while (true) {
        __try {
            Sleep(CHECK_INTERVAL_MS);

            auto players = g_playerMgr.GetAllPlayers();

            for (int sid : players) {
                // Skip if recently flagged
                if (g_playerMgr.IsFlagged(sid)) {
                    continue;
                }

                bool should_kick = false;
                std::string kick_reason = "";

                // ===== AFK CHECK =====
                if (g_playerMgr.IsAFK(sid)) {
                    should_kick = true;
                    kick_reason = "[AC] AFK Timeout - Kicked";
                }
                // ===== AUTOCLICK CHECK =====
                else if (g_playerMgr.IsAutoClick(sid)) {
                    should_kick = true;
                    kick_reason = "[AC] AutoClick Detected - Kicked";
                }

                // Execute kick if needed
                if (should_kick && KickPlayer) {
                    __try {
                        KickPlayer(nullptr, sid, kick_reason. c_str());
                        
                        char buffer[256];
                        sprintf_s(buffer, sizeof(buffer), 
                                 "[AC_INFO] Kicked player %d: %s\n", 
                                 sid, kick_reason. c_str());
                        OutputDebugStringA(buffer);
                        
                        g_playerMgr.FlagPlayer(sid);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        OutputDebugStringA("[AC_ERROR] Exception during kick\n");
                    }
                }
            }

            // Cleanup flagged players
            Sleep(FLAGGED_CLEANUP_MS);
            auto flagged_players = g_playerMgr.GetAllPlayers();
            for (int sid : flagged_players) {
                if (g_playerMgr. IsFlagged(sid)) {
                    g_playerMgr.RemovePlayer(sid);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            OutputDebugStringA("[AC_ERROR] Exception in CheckerThread\n");
            Sleep(1000);  // Prevent infinite loop on crash
        }
    }
    return 0;
}

// ========================= HOOKING UTILITIES ==================================

bool WriteJMP(DWORD addr, void* func) {
    __try {
        // Validate addresses
        if (addr == 0 || func == nullptr) {
            OutputDebugStringA("[AC_ERROR] Invalid address for hooking\n");
            return false;
        }

        // Make memory writable
        DWORD old = 0;
        if (! VirtualProtect((void*)addr, 5, PAGE_EXECUTE_READWRITE, &old)) {
            OutputDebugStringA("[AC_ERROR] VirtualProtect failed\n");
            return false;
        }

        // Write JMP instruction: 0xE9 + relative offset
        *(BYTE*)(addr) = 0xE9;
        *(DWORD*)(addr + 1) = (DWORD)func - addr - 5;

        // Restore original protection
        DWORD dummy;
        VirtualProtect((void*)addr, 5, old, &dummy);

        // Log success
        char buffer[256];
        sprintf_s(buffer, sizeof(buffer), 
                 "[AC_INFO] Hook written at 0x%08X → 0x%08X\n", 
                 addr, (DWORD)func);
        OutputDebugStringA(buffer);

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        OutputDebugStringA("[AC_ERROR] Exception in WriteJMP\n");
        return false;
    }
}

// ========================= DLL ENTRY POINT ===================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    switch (reason) {
        
    case DLL_PROCESS_ATTACH:
    {
        OutputDebugStringA("[AC_INFO] ========================================\n");
        OutputDebugStringA("[AC_INFO] Anti-Cheat System Starting\n");
        OutputDebugStringA("[AC_INFO] ========================================\n");

        // Store original function pointers
        oPacketHandler = (PacketHandler_t)ADDR_PACKET_HANDLER;
        KickPlayer = (KickFunc_t)ADDR_KICK_FUNC;

        // Log configuration
        char buffer[512];
        sprintf_s(buffer, sizeof(buffer),
                 "[AC_CONFIG]\n"
                 "  Packet Handler: 0x%08X\n"
                 "  Kick Function:  0x%08X\n"
                 "  Fire Opcode:    0x%02X\n"
                 "  AFK Timeout:    %d seconds\n"
                 "  Variance Max:   %. 1f ms\n"
                 "  Avg Max:        %d ms\n"
                 "  Burst:          %d shots in %d ms\n",
                 ADDR_PACKET_HANDLER, ADDR_KICK_FUNC, OP_FIRE,
                 AFK_TIMEOUT_SEC, AUTOCLICK_VAR_MAX, AUTOCLICK_AVG_MAX,
                 BURST_FIRE_COUNT, BURST_FIRE_WINDOW_MS);
        OutputDebugStringA(buffer);

        // Install hook
        if (!WriteJMP(ADDR_PACKET_HANDLER, hkPacketHandler)) {
            OutputDebugStringA("[AC_ERROR] Failed to hook packet handler!\n");
            return FALSE;
        }

        // Start checker thread
        HANDLE hThread = CreateThread(NULL, 0, CheckerThread, NULL, 0, NULL);
        if (hThread) {
            SetThreadPriority(hThread, THREAD_PRIORITY_ABOVE_NORMAL);
            CloseHandle(hThread);
            OutputDebugStringA("[AC_INFO] Checker thread started\n");
        } else {
            OutputDebugStringA("[AC_ERROR] Failed to create checker thread!\n");
            return FALSE;
        }

        OutputDebugStringA("[AC_INFO] Anti-Cheat System Ready!\n");
        break;
    }

    case DLL_PROCESS_DETACH:
    {
        OutputDebugStringA("[AC_INFO] Anti-Cheat System Unloading\n");
        OutputDebugStringA("[AC_INFO] ========================================\n");
        break;
    }

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}

// ==================== DEBUGGING / TESTING EXPORTS ===========================

// Export for manual testing
extern "C" {
    __declspec(dllexport) void SimulateShoot(int sid) {
        g_playerMgr. MarkActive(sid);
        g_playerMgr.LogShoot(sid);
    }

    __declspec(dllexport) int GetPlayerCount() {
        return (int)g_playerMgr.GetPlayerCount();
    }

    __declspec(dllexport) void GetStats(int sid, int* shots, double* avg) {
        g_playerMgr.GetPlayerStats(sid, *shots, *avg);
    }

    __declspec(dllexport) bool GetIsAutoClick(int sid) {
        return g_playerMgr. IsAutoClick(sid);
    }

    __declspec(dllexport) bool GetIsAFK(int sid) {
        return g_playerMgr.IsAFK(sid);
    }
}

// ============================================================================