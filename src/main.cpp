#include <cpr/cpr.h>
#include <fmt/core.h>
#include <fmt/ostream.h>

#include "json.hpp"

#include <string>
#include <vector>
#include <chrono>
#include <future>
#include <thread>
#include <atomic>
#include <algorithm>
#include <stdexcept>
#include <fstream>
#include <regex>


using namespace std::chrono_literals;
using json = nlohmann::json;

struct Target
{
    std::string ip;
    int port;

    bool operator<(const Target& other) const
    {
        if (ip != other.ip)
            return ip < other.ip;
        return port < other.port;
    }

    bool operator==(const Target& other) const
    {
        return ip == other.ip && port == other.port;
    }
};


struct VerifiedInstance
{
    Target target{};
    std::string tags_error;
    json tags_data;
    std::string ps_error;
    json ps_data;
    bool interrogation_succeeded = false;

    explicit VerifiedInstance(Target t) : target(std::move(t)) {}

    VerifiedInstance() = default;
};

void fetch_instance_details(VerifiedInstance& instance_data, const std::chrono::milliseconds timeout)
{
    const std::string base_url = fmt::format("http://{}:{}", instance_data.target.ip, instance_data.target.port);
    bool tags_ok = false;
    bool ps_ok = false;

    auto tags_future = cpr::GetAsync(cpr::Url{base_url + "/api/tags"}, cpr::Timeout{timeout});
    auto ps_future = cpr::GetAsync(cpr::Url{base_url + "/api/ps"}, cpr::Timeout{timeout});

    cpr::Response tags_resp = tags_future.get();
    if (tags_resp.error.code == cpr::ErrorCode::OK && tags_resp.status_code == 200)
    {
        try
        {
            instance_data.tags_data = json::parse(tags_resp.text);
            tags_ok = true; // Mark success
        }
        catch (const json::parse_error& e)
        {
            instance_data.tags_error = fmt::format("Tags JSON Parse Error: {}", e.what());
        }
    }
    else
    {
        instance_data.tags_error = fmt::format("Tags Request Failed: status={}, error={}",
                                               tags_resp.status_code, tags_resp.error.message);
    }

    cpr::Response ps_resp = ps_future.get();
    if (ps_resp.error.code == cpr::ErrorCode::OK && ps_resp.status_code == 200)
    {
        try
        {
            instance_data.ps_data = json::parse(ps_resp.text);
            ps_ok = true; // Mark success
        }
        catch (const json::parse_error& e)
        {
            instance_data.ps_error = fmt::format("PS JSON Parse Error: {}", e.what());
        }
    }
    else
    {
        instance_data.ps_error = fmt::format("PS Request Failed: status={}, error={}",
                                             ps_resp.status_code, ps_resp.error.message);
    }

    instance_data.interrogation_succeeded = tags_ok || ps_ok;
}



int main(int argc, char** argv)
{
    std::string input_filename = "res.txt";
    size_t max_concurrent = 500;

    if (argc > 1 && std::string(argv[1]) != "-h" && std::string(argv[1]) != "--help")
    {
        input_filename = argv[1];
    }
    if (argc > 2)
    {
        try
        {
            max_concurrent = std::stoul(argv[2]);
            if (max_concurrent == 0)
            {
                fmt::print(stderr, "Warning: max_concurrent cannot be 0. Setting to 1.\n");
                max_concurrent = 1;
            }
        }
        catch (const std::invalid_argument& e)
        {
            fmt::print(stderr, "Error: Invalid value for max_concurrent: '{}'. Using default: {}. ({})\n", argv[2],
                       max_concurrent, e.what());
        }
        catch (const std::out_of_range& e)
        {
            fmt::print(stderr, "Error: Value for max_concurrent out of range: '{}'. Using default: {}. ({})\n", argv[2],
                       max_concurrent, e.what());
        }
    }

    if (argc == 1 || (argc > 1 && (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help")) || (argc > 3))
    {
        if (argc > 3)
        {
            fmt::print(stderr, "Error: Too many arguments provided.\n\n");
        }
        fmt::print(stderr, "Usage: {} [input_file] [max_concurrent]\n", argv[0]);
        fmt::print(stderr, "  [input_file]:     File containing masscan results (grepable format -oG). Default: {}\n",
                   input_filename);
        fmt::print(stderr, "  [max_concurrent]: Max parallel initial scan requests. Default: {}\n", max_concurrent);
        fmt::print(stderr, "Example: {} masscan_results.txt 1000\n", argv[0]);
        return (argc > 1 && (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help")) ? 0 : 1;
    }


    std::vector<Target> candidates;
    std::ifstream input_file(input_filename);
    if (!input_file.is_open())
    {
        fmt::print(stderr, "Error: Could not open input file: {}\n", input_filename);
        return 1;
    }

    std::string line;
    std::regex masscan_line_regex(R"(Host:\s*([0-9.]+)\s*\(.*\)\s*Ports:\s*([0-9]+)\/open\/)");

    fmt::print("Reading candidates from: {}\n", input_filename);
    while (std::getline(input_file, line))
    {
        std::smatch match;
        if (std::regex_search(line, match, masscan_line_regex))
        {
            if (match.size() == 3)
            {
                // match[0] is the whole string, match[1] is IP, match[2] is Port
                try
                {
                    candidates.push_back({match[1].str(), std::stoi(match[2].str())});
                }
                catch (const std::invalid_argument& e)
                {
                    fmt::print(stderr, "[Warning] Failed to parse port number on line: '{}' - {}\n", line, e.what());
                } catch (const std::out_of_range& e)
                {
                    fmt::print(stderr, "[Warning] Port number out of range on line: '{}' - {}\n", line, e.what());
                }
            }
        }
        else
        {
            if (!line.empty() && line[0] != '#')
            {
                // fmt::print(stderr, "[Debug] Skipping non-matching line: {}\n", line);
            }
        }
    }
    input_file.close();

    if (candidates.empty())
    {
        fmt::print(stderr, "Error: No valid candidates found in the input file.\n");
        return 1;
    }


    constexpr std::string_view initial_probe_endpoint = "/api/tags";
    constexpr auto request_timeout = 2s; // timeout for initial probe

    fmt::print("Read {} candidates.\n", candidates.size());
    fmt::print("--- Phase 1: Initial Verification ---\n");
    fmt::print("Using max concurrency: {}\n", max_concurrent);
    fmt::print("Probing endpoint: {}\n", initial_probe_endpoint);
    fmt::print("Timeout per request: {}ms\n",
               std::chrono::duration_cast<std::chrono::milliseconds>(request_timeout).count());
    fmt::print("-------------------------------------\n");

    std::vector<std::pair<size_t, cpr::AsyncResponse> > futures;
    std::atomic<size_t> current_candidate_index{0};
    std::atomic<uint64_t> total_probes_launched{0};
    std::atomic<uint64_t> total_probes_completed{0};
    std::vector<Target> potential_instances;
    std::mutex potential_instances_mutex;

    auto start_time = std::chrono::steady_clock::now();

    while (total_probes_completed < candidates.size())
    {
        // launch new probes if we have capacity
        while (futures.size() < max_concurrent && current_candidate_index < candidates.size())
        {
            size_t index_to_probe = current_candidate_index.fetch_add(1);
            if (index_to_probe >= candidates.size())
            {
                //d race condition where another thread already grabbed the last item
                break;
            }

            const auto& [ip, port] = candidates[index_to_probe];
            const std::string url_string = fmt::format("http://{}:{}{}", ip, port,
                                                       initial_probe_endpoint);

            futures.emplace_back(index_to_probe, cpr::GetAsync(cpr::Url{url_string}, cpr::Timeout{request_timeout}));
            ++total_probes_launched;
        }

        if (!futures.empty())
        {
            auto it = std::ranges::find_if(futures, [] (const auto& pair) {
                return pair.second.wait_for(0ms) == std::future_status::ready;
            });

            if (it != futures.end())
            {
                size_t completed_index = it->first;
                cpr::Response response = it->second.get();
                ++total_probes_completed;

                const auto& probed_target = candidates[completed_index];

                if (response.error.code == cpr::ErrorCode::OK && response.status_code == 200)
                {
                    if (response.text.find("\"models\"") != std::string::npos)
                    {
                        fmt::print("[POTENTIAL] Ollama found at {}:{} (Initial probe OK)\n", probed_target.ip, probed_target.port);

                        {
                            std::scoped_lock lock(potential_instances_mutex);
                            potential_instances.push_back(probed_target);
                        }
                    }
                    else
                    {
                        // fmt::print("[DEBUG] {} -> Status 200, but no 'models' key found in response for {}\n",
                        //            probed_target, initial_probe_endpoint);
                    }
                }
                else if (response.error.code == cpr::ErrorCode::OPERATION_TIMEDOUT)
                {
                    // fmt::print("[DEBUG] {} -> Timeout\n", probed_target);
                }
                else if (response.error.code != cpr::ErrorCode::OK)
                {
                    // fmt::print("[DEBUG] {} -> Error: {}\n", probed_target, response.error.message);
                }
                else // Other non-200 status codes
                {
                    // fmt::print("[DEBUG] {} -> Status: {}\n", probed_target, response.status_code);
                }

                futures.erase(it);

                // progress update logic
                if (total_probes_completed % 100 == 0 || total_probes_completed == candidates.size())
                {
                    auto current_time = std::chrono::steady_clock::now();
                    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time).
                            count();
                    double rate = (elapsed_ms > 0)
                                      ? static_cast<double>(total_probes_completed) * 1000.0 / elapsed_ms
                                      : 0.0;

                    fmt::print("[Progress] Checked: {}/{}, Potential: {}, Rate: {:.1f} req/s\n",
                               total_probes_completed.load(), candidates.size(), potential_instances.size(), rate);
                }
            }
            else
            {
                if (futures.size() >= max_concurrent || current_candidate_index >= candidates.size())
                {
                    std::this_thread::sleep_for(10ms);
                }
            }
        }
        else if (current_candidate_index >= candidates.size())
        {
            // all launched, none processing, and all completed, get out
            break; // should exit based on outer loop condition, but safer to break
        }
        else
        {
            // no futures running, but candidates remain, launch loop
            std::this_thread::sleep_for(5ms);
        }
    } // end of phase 1

    auto phase1_end_time = std::chrono::steady_clock::now();
    auto phase1_duration = std::chrono::duration_cast<std::chrono::seconds>(phase1_end_time - start_time);

    auto details_request_timeout = 5s;

    fmt::print("-------------------------------------\n");
    fmt::print("--- Phase 1 Complete ---\n");
    fmt::print("Checked {} candidates in {} seconds.\n", total_probes_completed.load(), phase1_duration.count());
    fmt::print("Found {} potential Ollama instances.\n", potential_instances.size());


    std::vector<VerifiedInstance> final_results;
    if (!potential_instances.empty())
    {
        fmt::print("--- Phase 2: Interrogating Potential Instances ---\n");
        fmt::print("Timeout per request: {}ms\n", details_request_timeout.count());
        fmt::print("--------------------------------------------------\n");

        std::sort(potential_instances.begin(), potential_instances.end());
        potential_instances.erase(std::unique(potential_instances.begin(), potential_instances.end()),
                                  potential_instances.end());
        fmt::print("Unique potential instances to interrogate: {}\n", potential_instances.size());


        size_t interrogated_count = 0;
        final_results.reserve(potential_instances.size());
        for (const auto& target : potential_instances)
        {
            fmt::print("[Interrogating] {}:{}...\n", target.ip, target.port);
            VerifiedInstance instance_data(target);

            fetch_instance_details(instance_data, details_request_timeout);
            final_results.push_back(std::move(instance_data));
            interrogated_count++;
            fmt::print("[Progress] Interrogated: {}/{}\n", interrogated_count, potential_instances.size());
        }
        fmt::print("--------------------------------------------------\n");
        fmt::print("--- Phase 2 Complete ---\n");
    }

    auto end_time = std::chrono::steady_clock::now();
    auto total_duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);

    fmt::print("=====================================\n");
    fmt::print("Scan Finished\n");
    fmt::print("Total duration: {} seconds\n", total_duration.count());

    if (final_results.empty())
    {
        fmt::print("No verified Ollama instances found.\n");
    }
    else
    {
        fmt::print("Found {} verified Ollama instances:\n", final_results.size());
        fmt::print("-------------------------------------\n");
        for (const auto& instance : final_results)
        {
            fmt::print("Instance: http://{}:{}\n", instance.target.ip, instance.target.port);

            fmt::print("  Installed Models (/api/tags):\n");
            if (!instance.tags_error.empty())
            {
                fmt::print("    Error: {}\n", instance.tags_error);
            }
            else if (instance.tags_data.is_object() && instance.tags_data.contains("models") && instance.tags_data[
                         "models"].is_array())
            {
                if (instance.tags_data["models"].empty())
                {
                    fmt::print("    (No models installed)\n");
                }
                else
                {
                    for (const auto& model : instance.tags_data["models"])
                    {
                        std::string name = model.value("name", "N/A");
                        std::string param_size = "?";
                        std::string quant_level = "?";

                        if (model.is_object() && model.contains("details") && model["details"].is_object())
                        {
                            param_size = model["details"].value("parameter_size", "?");
                            quant_level = model["details"].value("quantization_level", "?");
                        }
                        fmt::print("    - {} (Size: {}, Quant: {})\n", name, param_size, quant_level);
                    }
                }
            }
            else if (!instance.tags_data.is_null())
            {
                fmt::print("    (Unexpected JSON format or no 'models' array)\n");
                // fmt::print("    Raw JSON: {}\n", instance.tags_data.dump(2));
            }
            else
            {
                // shouldnt happen if tags_error is empty, but whatrveer
                fmt::print("    (No data retrieved)\n");
            }

            fmt::print("  Running Models (/api/ps):\n");
            if (!instance.ps_error.empty())
            {
                fmt::print("    Error: {}\n", instance.ps_error);
            }
            else if (instance.ps_data.is_object() && instance.ps_data.contains("models") && instance.ps_data["models"].
                     is_array())
            {
                if (instance.ps_data["models"].empty())
                {
                    fmt::print("    (No models currently running/loaded)\n");
                }
                else
                {
                    for (const auto& model : instance.ps_data["models"])
                    {
                        std::string name = model.value("name", "N/A");
                        std::string param_size = "?";
                        std::string quant_level = "?";
                        std::string expires_at = model.value("expires_at", "");

                        if (model.is_object() && model.contains("details") && model["details"].is_object())
                        {
                            param_size = model["details"].value("parameter_size", "?");
                            quant_level = model["details"].value("quantization_level", "?");
                        }

                        fmt::print("    - {} (Size: {}, Quant: {})", name, param_size, quant_level);

                        if (!expires_at.empty() && expires_at != "0001-01-01T00:00:00Z")
                        {
                            fmt::print(" [Expires: {}]", expires_at);
                        }
                        fmt::print("\n");
                    }
                }
            }
            else if (!instance.ps_data.is_null())
            {
                fmt::print("    (Unexpected JSON format or no 'models' array)\n");
                // fmt::print("    Raw JSON: {}\n", instance.ps_data.dump(2));
            }
            else
            {
                fmt::print("    (No data retrieved)\n");
            }
            fmt::print("-------------------------------------\n");
        }
    }

    return 0;
}
