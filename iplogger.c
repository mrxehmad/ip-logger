#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <time.h>
#include <signal.h>
#include <stdbool.h>
#include <jansson.h>

#define MAX_IP_LEN 64
#define MAX_COUNTRY_LEN 8
#define MAX_ASN_LEN 128
#define TIMEOUT_SEC 5L
#define DEFAULT_INTERVAL 15  // Default polling interval in minutes
#define DEFAULT_LOG_FILE "ip_log.json"

// API URLs to fetch IP information
const char* API_URLS[] = {
    "http://ip-api.com/json/",
    "https://ipinfo.io/json/",
    "https://ifconfig.me/all.json"
};
#define NUM_APIS 3

// Structure to store response data
typedef struct {
    char* data;
    size_t size;
} ResponseData;

// Structure to store IP information
typedef struct {
    char ip[MAX_IP_LEN];
    char country[MAX_COUNTRY_LEN];
    char asn[MAX_ASN_LEN];
} IPInfo;

// Global variables
volatile sig_atomic_t keep_running = 1;
IPInfo current_ip_info = {0};
char* log_file_path = NULL;

// Signal handler for graceful termination
void handle_signal(int sig) {
    keep_running = 0;
}

// Callback function for cURL
size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t real_size = size * nmemb;
    ResponseData* response = (ResponseData*)userp;
    
    char* ptr = realloc(response->data, response->size + real_size + 1);
    if (!ptr) {
        fprintf(stderr, "Failed to allocate memory for response\n");
        return 0;
    }
    
    response->data = ptr;
    memcpy(&(response->data[response->size]), contents, real_size);
    response->size += real_size;
    response->data[response->size] = 0;
    
    return real_size;
}

// Function to make HTTP requests
char* make_http_request(const char* url) {
    CURL* curl;
    CURLcode res;
    ResponseData response = {0};
    
    response.data = malloc(1);
    if (!response.data) {
        fprintf(stderr, "Failed to allocate memory for response\n");
        return NULL;
    }
    response.size = 0;
    
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, TIMEOUT_SEC);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "ip-change-logger/1.0");
        
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        if (res != CURLE_OK) {
            fprintf(stderr, "cURL request failed: %s\n", curl_easy_strerror(res));
            free(response.data);
            return NULL;
        }
    } else {
        free(response.data);
        return NULL;
    }
    
    return response.data;
}

// Parse IP API response
bool parse_ip_api_response(const char* json_data, IPInfo* ip_info) {
    json_error_t error;
    json_t* root = json_loads(json_data, 0, &error);
    
    if (!root) {
        fprintf(stderr, "JSON parsing error: %s\n", error.text);
        return false;
    }
    
    json_t* status = json_object_get(root, "status");
    if (!status || !json_is_string(status) || strcmp(json_string_value(status), "success") != 0) {
        json_decref(root);
        return false;
    }
    
    json_t* query = json_object_get(root, "query");
    json_t* country_code = json_object_get(root, "countryCode");
    json_t* as_info = json_object_get(root, "as");
    
    if (query && json_is_string(query)) {
        strncpy(ip_info->ip, json_string_value(query), MAX_IP_LEN - 1);
    }
    
    if (country_code && json_is_string(country_code)) {
        strncpy(ip_info->country, json_string_value(country_code), MAX_COUNTRY_LEN - 1);
    }
    
    if (as_info && json_is_string(as_info)) {
        strncpy(ip_info->asn, json_string_value(as_info), MAX_ASN_LEN - 1);
    }
    
    json_decref(root);
    return true;
}

// Parse ipinfo.io response
bool parse_ipinfo_response(const char* json_data, IPInfo* ip_info) {
    json_error_t error;
    json_t* root = json_loads(json_data, 0, &error);
    
    if (!root) {
        fprintf(stderr, "JSON parsing error: %s\n", error.text);
        return false;
    }
    
    json_t* ip = json_object_get(root, "ip");
    json_t* country = json_object_get(root, "country");
    json_t* org = json_object_get(root, "org");
    
    if (ip && json_is_string(ip)) {
        strncpy(ip_info->ip, json_string_value(ip), MAX_IP_LEN - 1);
    }
    
    if (country && json_is_string(country)) {
        strncpy(ip_info->country, json_string_value(country), MAX_COUNTRY_LEN - 1);
    }
    
    if (org && json_is_string(org)) {
        strncpy(ip_info->asn, json_string_value(org), MAX_ASN_LEN - 1);
    }
    
    json_decref(root);
    return true;
}

// Parse ifconfig.me response
bool parse_ifconfig_response(const char* json_data, IPInfo* ip_info) {
    json_error_t error;
    json_t* root = json_loads(json_data, 0, &error);
    
    if (!root) {
        fprintf(stderr, "JSON parsing error: %s\n", error.text);
        return false;
    }
    
    json_t* ip_addr = json_object_get(root, "ip_addr");
    
    if (ip_addr && json_is_string(ip_addr)) {
        strncpy(ip_info->ip, json_string_value(ip_addr), MAX_IP_LEN - 1);
        // Note: ifconfig.me doesn't provide country or ASN
        // Leave these fields empty
    }
    
    json_decref(root);
    return true;
}

// Function to parse API responses
bool parse_api_response(int api_index, const char* json_data, IPInfo* ip_info) {
    switch (api_index) {
        case 0:
            return parse_ip_api_response(json_data, ip_info);
        case 1:
            return parse_ipinfo_response(json_data, ip_info);
        case 2:
            return parse_ifconfig_response(json_data, ip_info);
        default:
            return false;
    }
}

// Check if the IP has changed
bool ip_changed(const IPInfo* prev_ip, const IPInfo* new_ip) {
    return strcmp(prev_ip->ip, new_ip->ip) != 0;
}

// Log IP information to JSON file (now logs every check, not just changes)
void log_ip_change(const IPInfo* ip_info) {
    FILE* file;
    json_t* root = NULL;
    json_t* entry = NULL;
    json_error_t error;
    time_t now;
    struct tm* timeinfo;
    char timestamp[64];
    
    // Get current time
    time(&now);
    timeinfo = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    // Create new entry
    entry = json_object();
    json_object_set_new(entry, "timestamp", json_string(timestamp));
    json_object_set_new(entry, "ip", json_string(ip_info->ip));
    json_object_set_new(entry, "country", json_string(ip_info->country));
    json_object_set_new(entry, "asn", json_string(ip_info->asn));
    
    // Try to load existing log file
    file = fopen(log_file_path, "r");
    if (file) {
        char buffer[8192];
        size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, file);
        buffer[bytes_read] = '\0';
        fclose(file);
        
        if (bytes_read > 0) {
            root = json_loads(buffer, 0, &error);
            if (!root) {
                // If parsing fails, create a new array
                root = json_array();
            }
        } else {
            root = json_array();
        }
    } else {
        root = json_array();
    }
    
    // Add new entry
    json_array_append_new(root, entry);
    
    // Write back to file
    file = fopen(log_file_path, "w");
    if (file) {
        char* json_output = json_dumps(root, JSON_INDENT(2));
        fprintf(file, "%s\n", json_output);
        free(json_output);
        fclose(file);
    } else {
        fprintf(stderr, "Failed to open log file for writing: %s\n", log_file_path);
    }
    
    json_decref(root);
    
    // Also print to stdout
    printf("[%s] IP check: %s (Country: %s, ASN: %s)\n", 
           timestamp, ip_info->ip, ip_info->country, ip_info->asn);
}

// Fetch current IP information
bool fetch_current_ip(IPInfo* ip_info) {
    memset(ip_info, 0, sizeof(IPInfo));
    
    for (int i = 0; i < NUM_APIS; i++) {
        char* response = make_http_request(API_URLS[i]);
        if (response) {
            bool success = parse_api_response(i, response, ip_info);
            free(response);
            
            if (success && strlen(ip_info->ip) > 0) {
                return true;
            }
            
            // Wait before trying next API
            if (i < NUM_APIS - 1) {
                sleep(1);
            }
        }
    }
    
    return false;
}

void print_usage(const char* program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("Options:\n");
    printf("  -t <minutes>      Polling interval in minutes (default: %d)\n", DEFAULT_INTERVAL);
    printf("  -o <file>         Output log file (default: %s)\n", DEFAULT_LOG_FILE);
    printf("  -h                Show this help\n");
}

int main(int argc, char* argv[]) {
    int interval = DEFAULT_INTERVAL;
    log_file_path = strdup(DEFAULT_LOG_FILE);
    int opt;
    
    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "t:o:h")) != -1) {
        switch (opt) {
            case 't':
                interval = atoi(optarg);
                if (interval <= 0) {
                    fprintf(stderr, "Invalid interval: %s\n", optarg);
                    print_usage(argv[0]);
                    return 1;
                }
                break;
            case 'o':
                free(log_file_path);
                log_file_path = strdup(optarg);
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    printf("IP Change Logger started. Polling every %d minutes. Logging to %s\n", 
           interval, log_file_path);
    
    // Main polling loop
    while (keep_running) {
        IPInfo new_ip_info = {0};
        
        if (fetch_current_ip(&new_ip_info)) {
            // Check if this is the first run
            if (strlen(current_ip_info.ip) == 0) {
                // Log the initial IP
                log_ip_change(&new_ip_info);
                memcpy(&current_ip_info, &new_ip_info, sizeof(IPInfo));
            } else if (ip_changed(&current_ip_info, &new_ip_info)) {
                // Log when IP has changed and update current IP info
                printf("[INFO] IP has changed from %s to %s\n", current_ip_info.ip, new_ip_info.ip);
                log_ip_change(&new_ip_info);
                memcpy(&current_ip_info, &new_ip_info, sizeof(IPInfo));
            } else {
                // Log anyway even if IP is the same
                log_ip_change(&new_ip_info);
                // No need to update current_ip_info since it's the same
            }
        } else {
            fprintf(stderr, "Failed to fetch IP information\n");
        }
        
        // Sleep for the specified interval
        for (int i = 0; i < interval * 60 && keep_running; i++) {
            sleep(1);
        }
    }
    
    // Clean up
    curl_global_cleanup();
    free(log_file_path);
    
    printf("IP Change Logger stopped\n");
    return 0;
}
