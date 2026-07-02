#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <memory>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>

enum class LogLevel { INFO, WARN, ERROR };

void log_message(LogLevel level, const std::string& message) {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    auto duration = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count() % 1000;

    std::string lvl_str;
    switch (level) {
        case LogLevel::INFO:  lvl_str = "[INFO]"; break;
        case LogLevel::WARN:  lvl_str = "[WARN]"; break;
        case LogLevel::ERROR: lvl_str = "[ERR ]"; break;
    }
    
    struct tm buf{};
#if defined(_WIN32) || defined(_WIN64)
    localtime_s(&buf, &time_t_now);
#else
    localtime_r(&time_t_now, &buf);
#endif

    std::cout << std::put_time(&buf, "%Y-%m-%d %H:%M:%S")
              << "." << std::setw(3) << std::setfill('0') << millis
              << " " << lvl_str << " " << message << std::endl;
}

class ChannelWrapper {
    ssh_channel channel;
public:
    explicit ChannelWrapper(ssh_session session) {
        channel = channel_new(session);
        if (channel && channel_open_session(channel) != SSH_OK) {
            channel_free(channel);
            channel = nullptr;
        }
    }
    ~ChannelWrapper() { if (channel) { channel_close(channel); channel_free(channel); } }
    ssh_channel get() const { return channel; }
    bool is_valid() const { return channel != nullptr; }
};

class SFTPWrapper {
    sftp_session sftp;
public:
    explicit SFTPWrapper(ssh_session session) {
        sftp = sftp_new(session);
        if (sftp && sftp_init(sftp) != SSH_OK) {
            sftp_free(sftp);
            sftp = nullptr;
        }
    }
    ~SFTPWrapper() { if (sftp) sftp_free(sftp); }
    sftp_session get() const { return sftp; }
    bool is_valid() const { return sftp != nullptr; }
};

class SSHWrapper {
    ssh_session session;
public:
    SSHWrapper() { session = ssh_new(); }
    ~SSHWrapper() { if (session) { ssh_disconnect(session); ssh_free(session); } }
    ssh_session get() const { return session; }
    bool is_valid() const { return session != nullptr; }
};

class Arm64eVaultEngine {
private:
    std::string host;
    int port;
    std::string user;
    std::string pass;
    std::string local_vault_path;
    
    const std::vector<std::string> manifest_manifest = {
        "keychain-2.db",
        "com.apple.commcenter.device_config.plist",
        "ActivationRecords",
        "FairPlay",
        "Caches",
        "Databases"
    };

    bool execute_remote_command(ssh_session session, const std::string& command, std::string& output, int& exit_code) {
        ChannelWrapper chan(session);
        if (!chan.is_valid()) {
            log_message(LogLevel::ERROR, "Milopasscodev1 - Failed to allocate secure SSH channel context.");
            return false;
        }

        if (channel_request_exec(chan.get(), command.c_str()) != SSH_OK) {
            log_message(LogLevel::ERROR, "Milopasscodev1 - Execution request denied for command: " + command);
            return false;
        }

        char buffer[2048];
        output.clear();
        int bytes_read;
        while ((bytes_read = channel_read(chan.get(), buffer, sizeof(buffer), 0)) > 0) {
            output.append(buffer, bytes_read);
        }

        channel_send_eof(chan.get());
        exit_code = channel_get_exit_status(chan.get());
        return (bytes_read >= 0);
    }

    bool verify_hardware_integrity(ssh_session session) {
        std::string output;
        int exit_code = -1;
        
        log_message(LogLevel::INFO, "Milopasscodev1 - Querying remote Device-Tree environment via IORegistry query...");
        if (!execute_remote_command(session, "ioreg -p IODeviceTree -n choice -a 2>/dev/null", output, exit_code) || exit_code != 0) {
            log_message(LogLevel::WARN, "Milopasscodev1 - IORegistry returned non-zero status. Falling back to alternative environment probes.");
        }

        bool matched = (output.find("8020") != std::string::npos || 
                        output.find("8027") != std::string::npos || 
                        output.find("8030") != std::string::npos);

        if (!matched) {
            std::string nvram_out;
            execute_remote_command(session, "nvram -p 2>/dev/null", nvram_out, exit_code);
            matched = (nvram_out.find("8020") != std::string::npos || 
                       nvram_out.find("8027") != std::string::npos || 
                       nvram_out.find("8030") != std::string::npos);
        }

        return matched;
    }

    bool check_remote_source_files(ssh_session session) {
        std::string out;
        int exit_code = -1;
        
        std::vector<std::pair<std::string, std::string>> targets = {
            {"file", "/mnt2/Keychains/keychain-2.db"},
            {"file", "/mnt2/wireless/Library/Preferences/com.apple.commcenter.device_config.plist"},
            {"dir", "/mnt2/containers/Data/System/com.apple.mobileactivationd/Library/ActivationRecords"},
            {"dir", "/mnt2/containers/Data/System/com.apple.mobileactivationd/Library/Caches"},
            {"dir", "/mnt2/share/wireless/Library/Databases"},
            {"dir", "/mnt2/mobile/Library/FairPlay"}
        };

        for (const auto& target : targets) {
            std::string cmd = (target.first == "file") ? "[ -f " + target.second + " ] && [ -s " + target.second + " ] && [ -r " + target.second + " ]" 
                                                       : "[ -d " + target.second + " ] && [ -r " + target.second + " ]";
            execute_remote_command(session, cmd, out, exit_code);
            if (exit_code != 0) {
                log_message(LogLevel::ERROR, "Milopasscodev1 - Remote validation failed (Missing, empty, or unreadable): " + target.second);
                return false;
            }
        }
        
        std::string sqlite_check = "head -c 16 /mnt2/Keychains/keychain-2.db 2>/dev/null";
        execute_remote_command(session, sqlite_check, out, exit_code);
        if (out.find("SQLite format 3") == std::string::npos) {
            log_message(LogLevel::ERROR, "Milopasscodev1 - Remote validation failed: /mnt2/Keychains/keychain-2.db is not a valid SQLite3 database.");
            return false;
        }

        return true;
    }

    bool check_remote_storage_capacity(ssh_session session) {
        std::string out;
        int exit_code = -1;
        execute_remote_command(session, "du -s /mnt2/Keychains/keychain-2.db /mnt2/wireless/Library/Preferences/com.apple.commcenter.device_config.plist /mnt2/containers/Data/System/com.apple.mobileactivationd/Library/ActivationRecords /mnt2/containers/Data/System/com.apple.mobileactivationd/Library/Caches /mnt2/share/wireless/Library/Databases /mnt2/mobile/Library/FairPlay 2>/dev/null | awk '{sum+=$1} END {print sum}'", out, exit_code);
        long long required_space = std::strtoll(out.c_str(), nullptr, 10);

        execute_remote_command(session, "df /tmp | tail -n 1 | awk '{print $4}'", out, exit_code);
        long long available_space = std::strtoll(out.c_str(), nullptr, 10);

        if (required_space * 1.2 > available_space) {
            log_message(LogLevel::ERROR, "Milopasscodev1 - Insufficient storage space on remote /tmp filesystem partition.");
            return false;
        }
        return true;
    }

    std::string mount_and_prepare_writable_data(ssh_session session) {
        std::string block_output;
        int exit_code = -1;

        execute_remote_command(session, "which mount_apfs 2>/dev/null", block_output, exit_code);
        if (exit_code != 0 || block_output.empty()) {
            log_message(LogLevel::ERROR, "Milopasscodev1 - Critical tool missing: 'mount_apfs' command binary is not available in current environment execution paths.");
            return "";
        }

        execute_remote_command(session, "mkdir -p /mnt2 2>&1", block_output, exit_code);
        if (exit_code != 0) {
            log_message(LogLevel::ERROR, "Milopasscodev1 - Failed to instantiate absolute mount anchor directory path /mnt2: " + block_output);
            return "";
        }

        bool has_apfs_util = false;
        execute_remote_command(session, "which apfs.util 2>/dev/null", block_output, exit_code);
        if (exit_code == 0 && !block_output.empty()) {
            has_apfs_util = true;
        }

        execute_remote_command(session, "ls /dev/disk0s1s* /dev/disk1s* 2>/dev/null", block_output, exit_code);
        if (block_output.empty()) {
            execute_remote_command(session, "ls /dev/disk* 2>/dev/null", block_output, exit_code);
        }
        
        if (block_output.empty()) {
            log_message(LogLevel::ERROR, "Milopasscodev1 - Unable to query block storage architecture devices from device-nodes root.");
            return "";
        }

        std::stringstream ss(block_output);
        std::string disk_node;
        std::vector<std::string> candidates;
        while (ss >> disk_node) {
            if (disk_node.find("/dev/") != std::string::npos) {
                disk_node = disk_node.substr(disk_node.find_last_of('/') + 1);
            }
            disk_node.erase(std::remove(disk_node.begin(), disk_node.end(), '\n'), disk_node.end());
            disk_node.erase(std::remove(disk_node.begin(), disk_node.end(), '\r'), disk_node.end());
            
            if (disk_node.empty() || disk_node == "disk0" || disk_node == "disk1") {
                continue;
            }
            
            if (std::find(candidates.begin(), candidates.end(), disk_node) == candidates.end()) {
                candidates.push_back(disk_node);
            }
        }
        std::reverse(candidates.begin(), candidates.end());

        std::vector<std::string> mount_options_matrix = {
            "", 
            "-o rw",
            "-o rw,owners",
            "-w",
            "-o nomntsnap"
        };

        bool has_dd = false;
        execute_remote_command(session, "which dd 2>/dev/null", block_output, exit_code);
        if (exit_code == 0 && !block_output.empty()) {
            has_dd = true;
        }

        for (const auto& dev : candidates) {
            std::string full_device_path = "/dev/" + dev;
            log_message(LogLevel::INFO, "Milopasscodev1 - Evaluating absolute block storage reference node: " + full_device_path);

            if (has_apfs_util) {
                std::string crypto_check;
                execute_remote_command(session, "apfs.util -p " + full_device_path + " 2>/dev/null", crypto_check, exit_code);
                if (exit_code == 0 && (crypto_check.find("encrypted") != std::string::npos || crypto_check.find("Locked") != std::string::npos)) {
                    log_message(LogLevel::WARN, "Milopasscodev1 - Attempting Keybag expansion pipeline for locked crypto container node " + full_device_path);
                    std::string keybag_force_cmd = "reboot3 -m 2>/dev/null; signpost unlock 2>/dev/null; fvutil unlock " + full_device_path + " 2>/dev/null";
                    execute_remote_command(session, keybag_force_cmd, crypto_check, exit_code);
                }
            }

            for (const auto& opt : mount_options_matrix) {
                std::string cleanup_cmd = "umount -f /mnt2 2>/dev/null;";
                execute_remote_command(session, cleanup_cmd, block_output, exit_code);

                std::string mount_cmd = "mount_apfs " + opt + " " + full_device_path + " /mnt2 2>&1";
                execute_remote_command(session, mount_cmd, block_output, exit_code);

                if (exit_code != 0) {
                    std::string alternative_mount_cmd = "mount -t apfs " + opt + " " + full_device_path + " /mnt2 2>&1";
                    execute_remote_command(session, alternative_mount_cmd, block_output, exit_code);
                }

                if (exit_code == 0 || block_output.find("Resource busy") != std::string::npos) {
                    std::string verify_mount;
                    execute_remote_command(session, "mount 2>/dev/null", verify_mount, exit_code);
                    
                    if (verify_mount.find("/mnt2") != std::string::npos) {
                        std::string identity_check;
                        std::string identity_cmd = "[ -d /mnt2/private/var/mobile ] && [ -f /mnt2/Keychains/keychain-2.db ] && [ -d /mnt2/private/var/root ] && [ -d /mnt2/private/var/preferences ]";
                        execute_remote_command(session, identity_cmd, identity_check, exit_code);

                        if (exit_code == 0) {
                            std::string target_probe_file = "/mnt2/private/var/mobile/.rw_vault_probe";
                            bool real_hardware_write_verified = false;

                            if (has_dd) {
                                std::string rw_test_cmd = "dd if=/dev/zero of=" + target_probe_file + " bs=512 count=1 2>&1";
                                execute_remote_command(session, rw_test_cmd, block_output, exit_code);
                                
                                if (exit_code == 0) {
                                    std::string verify_size_cmd = "[ -s " + target_probe_file + " ] && head -c 4 " + target_probe_file;
                                    execute_remote_command(session, verify_size_cmd, block_output, exit_code);
                                    if (exit_code == 0) {
                                        real_hardware_write_verified = true;
                                    }
                                }
                            }

                            if (!real_hardware_write_verified) {
                                std::string append_test_cmd = "echo 'MILO' >> " + target_probe_file + " 2>&1";
                                execute_remote_command(session, append_test_cmd, block_output, exit_code);
                                if (exit_code == 0) {
                                    std::string verify_append_cmd = "[ -s " + target_probe_file + " ] && grep -q 'MILO' " + target_probe_file + " 2>/dev/null";
                                    execute_remote_command(session, verify_append_cmd, block_output, exit_code);
                                    if (exit_code == 0) {
                                        real_hardware_write_verified = true;
                                    }
                                }
                            }

                            if (real_hardware_write_verified) {
                                std::string stat_output;
                                execute_remote_command(session, "stat -f %d /mnt2 /mnt2/private/var/mobile 2>/dev/null", stat_output, exit_code);
                                std::stringstream stat_ss(stat_output);
                                std::string dev_root, dev_sub;
                                if (stat_ss >> dev_root >> dev_sub && dev_root != dev_sub) {
                                    log_message(LogLevel::WARN, "Milopasscodev1 - Node " + full_device_path + " filtered out: Virtual filesystem layer (overlay/tmpfs/union) detected.");
                                    execute_remote_command(session, "rm -f " + target_probe_file + " 2>/dev/null", block_output, exit_code);
                                    continue;
                                }

                                execute_remote_command(session, "rm -f " + target_probe_file + " 2>/dev/null", block_output, exit_code);
                                log_message(LogLevel::INFO, "Milopasscodev1 - [+] Active Writable Data Partition found and locked on " + full_device_path + " inside core mount structural matrix.");
                                return full_device_path;
                            } else {
                                log_message(LogLevel::WARN, "Milopasscodev1 - Device node " + full_device_path + " linked successfully but failed strict dynamic write/read validation tests: " + block_output);
                            }
                        }
                    }
                }
            } else {
                log_message(LogLevel::WARN, "Milopasscodev1 - Mount options payload target configuration matrix pattern execution dropped context: (" + mount_cmd + ") -> System Response: " + block_output);
            }
        }
        execute_remote_command(session, "umount /mnt2 2>/dev/null", block_output, exit_code);
    }

    log_message(LogLevel::ERROR, "Milopasscodev1 - CRITICAL ERROR: High-level dynamic mount validation logic failed completely to secure writable APFS data node access context layer.");
    return "";
}

    bool download_secure_stream(ssh_session session, const std::string& remote_file, const std::string& local_file) {
        SFTPWrapper sftp(session);
        if (!sftp.is_valid()) {
            log_message(LogLevel::ERROR, "Milopasscodev1 - Failed to initialize subsystem channel descriptor for SFTP pipeline.");
            return false;
        }

        sftp_attributes attrs = sftp_stat(sftp.get(), remote_file.c_str());
        if (!attrs) {
            log_message(LogLevel::ERROR, "Milopasscodev1 - Remote descriptor access denied or missing file.");
            return false;
        }
        uint64_t remote_size = attrs->size;
        sftp_attributes_free(attrs);

        std::ios::openmode mode = std::ios::binary;
        uint64_t local_size = 0;
        
        std::ifstream test_file(local_file, std::ios::binary | std::ios::ate);
        if (test_file.is_open()) {
            local_size = test_file.tellg();
            test_file.close();
            if (local_size < remote_size) {
                mode |= std::ios::app;
                log_message(LogLevel::INFO, "Milopasscodev1 - Resuming existing interrupted stream from byte offset: " + std::to_string(local_size));
            } else if (local_size == remote_size) {
                log_message(LogLevel::INFO, "Milopasscodev1 - Local payload archive matches remote context size perfectly. Skipping transmission phase.");
                return true;
            } else {
                local_size = 0;
            }
        }

        if (local_size == 0) {
            mode |= std::ios::trunc;
        }

        sftp_file remote_fd = sftp_open(sftp.get(), remote_file.c_str(), O_RDONLY, 0);
        if (!remote_fd) {
            log_message(LogLevel::ERROR, "Milopasscodev1 - Remote descriptor access denied for payload vault transfer.");
            return false;
        }

        if (local_size > 0) {
            if (sftp_seek64(remote_fd, local_size) != 0) {
                log_message(LogLevel::ERROR, "Milopasscodev1 - Failed to seek remote SFTP channel position context.");
                sftp_close(remote_fd);
                return false;
            }
        }

        std::ofstream local_fd(local_file, mode);
        if (!local_fd.is_open()) {
            log_message(LogLevel::ERROR, "Milopasscodev1 - Local storage hardware I/O exception. Unable to allocate target container file.");
            sftp_close(remote_fd);
            return false;
        }

        std::vector<char> io_buffer(1024 * 128); 
        int bytes_transferred;
        while ((bytes_transferred = sftp_read(remote_fd, io_buffer.data(), io_buffer.size())) > 0) {
            local_fd.write(io_buffer.data(), bytes_transferred);
        }

        local_fd.close();
        sftp_close(remote_fd);
        return (bytes_transferred >= 0);
    }

    bool parse_and_validate_tar_headers(const std::string& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) return false;

        char header[512];
        std::vector<std::string> found_files;
        bool has_sqlite_header = false;

        while (file.read(header, 512)) {
            if (header[0] == '\0') {
                size_t zero_block_count = 1;
                while (zero_block_count < 2 && file.read(header, 512) && header[0] == '\0') {
                    zero_block_count++;
                }
                break;
            }

            long long header_checksum = 0;
            for (int i = 0; i < 512; ++i) {
                if (i >= 148 && i < 156) {
                    header_checksum += 32;
                } else {
                    header_checksum += static_cast<unsigned char>(header[i]);
                }
            }

            char chk_octal[9] = {0};
            std::memcpy(chk_octal, &header[148], 8);
            long long stored_checksum = std::strtoll(chk_octal, nullptr, 8);

            if (header_checksum != stored_checksum) {
                log_message(LogLevel::ERROR, "Milopasscodev1 - Tar parsing error: Header block checksum verification failed.");
                return false;
            }

            if (std::memcmp(&header[257], "ustar", 5) != 0) {
                log_message(LogLevel::ERROR, "Milopasscodev1 - Tar parsing error: Non-standard archive specification format.");
                return false;
            }

            std::string filename(header, 100);
            filename = filename.c_str(); 

            char size_octal[12] = {0};
            std::memcpy(size_octal, &header[124], 11);
            size_t filesize = std::strtoul(size_octal, nullptr, 8);

            for (const auto& required : manifest_manifest) {
                if (filename.find(required) != std::string::npos && filesize > 0) {
                    found_files.push_back(required);
                }
            }

            if (filename.find("keychain-2.db") != std::string::npos && filesize >= 16) {
                char sqlite_magic[16];
                file.read(sqlite_magic, 16);
                if (std::memcmp(sqlite_magic, "SQLite format 3", 15) == 0) {
                    has_sqlite_header = true;
                }
                size_t blocks_to_skip = (filesize - 16 + 511) / 512;
                file.seekg(blocks_to_skip * 512, std::ios::cur);
            } else {
                size_t blocks_to_skip = (filesize + 511) / 512;
                file.seekg(blocks_to_skip * 512, std::ios::cur);
            }
        }

        file.close();

        if (!has_sqlite_header) {
            log_message(LogLevel::ERROR, "Milopasscodev1 - Strict Manifest validation failure: Extracted keychain database is corrupted or missing signature block header.");
            return false;
        }

        for (const auto& required : manifest_manifest) {
            if (std::find(found_files.begin(), found_files.end(), required) == found_files.end()) {
                log_message(LogLevel::ERROR, "Milopasscodev1 - Strict Manifest validation failure: Crucial element missing or empty -> " + required);
                return false;
            }
        }

        log_message(LogLevel::INFO, "Milopasscodev1 - All manifest entries structural validation complete.");
        return true;
    }

    std::string calculate_vault_checksum(const std::string& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) return "";

        SHA256_CTX context;
        SHA256_Init(&context);
        std::vector<char> buffer(1024 * 64);
        while (file.read(buffer.data(), buffer.size()) || file.gcount()) {
            SHA256_Update(&context, buffer.data(), file.gcount());
        }

        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256_Final(digest, &context);

        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
        }
        return ss.str();
    }

public:
    explicit Arm64eVaultEngine(std::string r_host, int r_port, std::string r_user, std::string r_pass, std::string local_out)
        : host(std::move(r_host)), port(r_port), user(std::move(r_user)), pass(std::move(r_pass)), local_vault_path(std::move(local_out)) {}

    bool run_pipeline(const std::string& expected_sha256 = "") {
        log_message(LogLevel::INFO, "Milopasscodev1 - Initializing localized hardware environment socket probe on interface port: " + std::to_string(port));
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in target_addr{};
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(port);
        target_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        if (connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            log_message(LogLevel::ERROR, "Milopasscodev1 - Pipeline aborted: Interface connection refused on port " + std::to_string(port));
            close(sock);
            return false;
        }
        close(sock);

        SSHWrapper instance;
        if (!instance.is_valid()) {
            log_message(LogLevel::ERROR, "Milopasscodev1 - Failed to instantiate cryptographic context engine.");
            return false;
        }

        ssh_options_set(instance.get(), SSH_OPTIONS_HOST, host.c_str());
        ssh_options_set(instance.get(), SSH_OPTIONS_PORT, &port);
        ssh_options_set(instance.get(), SSH_OPTIONS_USER, user.c_str());

        log_message(LogLevel::INFO, "Milopasscodev1 - Connecting to secure endpoint layer...");
        if (ssh_connect(instance.get()) != SSH_OK || ssh_userauth_password(instance.get(), nullptr, pass.c_str()) != SSH_AUTH_SUCCESS) {
            log_message(LogLevel::ERROR, "Milopasscodev1 - Authentication exception: Tunnel link rejected access credentials.");
            return false;
        }

        if (!verify_hardware_integrity(instance.get())) {
            log_message(LogLevel::WARN, "Milopasscodev1 - Hardware platform verification tracking signature mismatches expected targets.");
        }

        std::string mounted_volume = mount_and_prepare_writable_data(instance.get());
        if (mounted_volume.empty()) {
            log_message(LogLevel::ERROR, "Milopasscodev1 - Critical pipeline error: Core APFS system topology could not be resolved.");
            return false;
        }

        if (!check_remote_source_files(instance.get())) {
            log_message(LogLevel::ERROR, "Milopasscodev1 - Remote file manifest verification failed prior to archive creation phase.");
            return false;
        }

        if (!check_remote_storage_capacity(instance.get())) {
            return false;
        }

        log_message(LogLevel::INFO, "Milopasscodev1 - Packing target transaction signatures and secure runtime database blobs into runtime cache...");
        std::string archive_payload = "tar -czf /tmp/.engine_vault.tar.gz "
                                      "-C /mnt2/containers/Data/System/com.apple.mobileactivationd/Library/ActivationRecords . "
                                      "-C /mnt2/containers/Data/System/com.apple.mobileactivationd/Library/Caches . "
                                      "-C /mnt2/wireless/Library/Preferences com.apple.commcenter.device_config.plist "
                                      "-C /mnt2/share/wireless/Library/Databases . "
                                      "-C /mnt2/Keychains keychain-2.db "
                                      "-C /mnt2/mobile/Library/FairPlay . 2>&1";

        std::string dump_out;
        int command_exit_status = -1;
        if (!execute_remote_command(instance.get(), archive_payload, dump_out, command_exit_status) || command_exit_status != 0 || dump_out.find("tar:") != std::string::npos) {
            log_message(LogLevel::ERROR, "Milopasscodev1 - Subsystem package aggregation failed with message content: " + dump_out);
            execute_remote_command(instance.get(), "rm -f /tmp/.engine_vault.tar.gz 2>/dev/null", dump_out, command_exit_status);
            return false;
        }

        log_message(LogLevel::INFO, "Milopasscodev1 - Streaming encrypted hardware data vault archive...");
        if (!download_secure_stream(instance.get(), "/tmp/.engine_vault.tar.gz", local_vault_path)) {
            log_message(LogLevel::ERROR, "Milopasscodev1 - Data corruption encountered during stream transmission pipeline.");
            execute_remote_command(instance.get(), "rm -f /tmp/.engine_vault.tar.gz 2>/dev/null", dump_out, command_exit_status);
            return false;
        }

        log_message(LogLevel::INFO, "Milopasscodev1 - Purging temporary allocation tables from remote engine storage...");
        execute_remote_command(instance.get(), "rm -f /tmp/.engine_vault.tar.gz 2>/dev/null", dump_out, command_exit_status);
        execute_remote_command(instance.get(), "umount /mnt2 2>/dev/null", dump_out, command_exit_status);

        std::string decompressed_vault = local_vault_path + ".tar";
        std::string decompress_cmd = "gzip -d -c " + local_vault_path + " > " + decompressed_vault;
        if (std::system(decompress_cmd.c_str()) != 0) {
            log_message(LogLevel::ERROR, "Milopasscodev1 - Local pipeline processing failed during archive expansion phase.");
            unlink(decompressed_vault.c_str());
            return false;
        }

        log_message(LogLevel::INFO, "Milopasscodev1 - Running post-extraction structural header manifest analysis...");
        if (!parse_and_validate_tar_headers(decompressed_vault)) {
            log_message(LogLevel::ERROR, "Milopasscodev1 - Structural manifest integrity check failed. Dropping transaction payload.");
            unlink(decompressed_vault.c_str());
            unlink(local_vault_path.c_str());
            return false;
        }
        unlink(decompressed_vault.c_str());

        std::string checksum = calculate_vault_checksum(local_vault_path);
        log_message(LogLevel::INFO, "Milopasscodev1 - VERIFIED_SHA256: " + checksum);

        if (!expected_sha256.empty()) {
            if (checksum != expected_sha256) {
                log_message(LogLevel::ERROR, "Milopasscodev1 - Cryptographic hash mismatch. Expected reference signature verification failed.");
                unlink(local_vault_path.c_str());
                return false;
            }
            log_message(LogLevel::INFO, "Milopasscodev1 - Cryptographic validation successful. Payload corresponds perfectly to signature reference.");
        }

        log_message(LogLevel::INFO, "Milopasscodev1 - Pipeline executed successfully without exceptions.");
        return true;
    }
};

int main(int argc, char* argv[]) {
    std::string run_host = (argc > 1) ? argv[1] : "127.0.0.1";
    int run_port = (argc > 2) ? std::stoi(argv[2]) : 2222;
    std::string run_user = (argc > 3) ? argv[3] : "root";
    std::string run_pass = (argc > 4) ? argv[4] : "alpine";
    std::string expected_hash = (argc > 5) ? argv[5] : "";

    std::string execution_vault = "./arm64e_production_vault.tar.gz";

    Arm64eVaultEngine engine(run_host, run_port, run_user, run_pass, execution_vault);
    
    if (engine.run_pipeline(expected_hash)) {
        std::cout << "[STATUS] MILOPASSCODEV1_CORE_BACKUP_SUCCESS" << std::endl;
        return 0;
    } else {
        std::cerr << "[STATUS] MILOPASSCODEV1_CORE_BACKUP_FAILURE" << std::endl;
        return 1;
    }
}