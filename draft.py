import os
import re
import glob
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import ipaddress
import json
import os
from ipwhois import IPWhois

CACHE_FILE = "whois_cache.json"

def load_cache():
    """Load cached WHOIS results from file."""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    return {}

cache = load_cache()

def save_cache(cache):
    """Save updated WHOIS cache to file."""
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=4)

# Folder containing Suricata logs
log_folder = "suricata_logs_2025-03-07-23-29-31_igc2"

# Find all log files in the folder (assuming they have a .log extension)
log_files = glob.glob(os.path.join(log_folder, "*.log.*"))

# Regular expression pattern to extract Suricata log fields
pattern = re.compile(
    r"(?P<timestamp>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)  \[\*\*\] "
    r"\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\] (?P<message>.*?) \[\*\*\] "
    r"\[Classification: (?P<classification>.*?)\] \[Priority: (?P<priority>\d+)\] "
    r"\{(?P<protocol>\w+)\} (?P<src_ip>[\d\.]+):(?P<src_port>\d+) -> (?P<dst_ip>[\d\.]+):(?P<dst_port>\d+)"
)

parsed_logs = []

# Function to check if an IP is private or public
def get_ip_type(ip):
    return "Private" if ipaddress.ip_address(ip).is_private else "Public"

def get_ip_description(ip):
    if ip == "172.18.3.254" or ip == "172.18.3.253" or ip == "172.18.3.252" : return "Routeur"
    if ipaddress.ip_address(ip) in ipaddress.ip_network("172.18.0.0/22"): return "Houzeau"
    if ipaddress.ip_address(ip) in ipaddress.ip_network("10.0.0.0/8") : return "UMONS"
    if ipaddress.ip_address(ip).is_global : 
        get_ip_whois(ip)
        return "Internet"
    else : return "Other"



def get_ip_whois(ip):
    """Check cache, fetch WHOIS data if necessary, and update cache."""
    
    if ip in cache:
        print(f"Cache hit for {ip}")
        return cache[ip]  # Return cached result

    print(f"Fetching WHOIS for {ip}")
    whois = IPWhois(ip)
    try:
        result = whois.lookup_rdap()  # Faster than WHOIS lookup
    except Exception as e:
        print(f"Error for {ip} : {e}")
        result = {ip: {
            "error": repr(e)
        } }

    cache[ip] = result  # Store result in cache
    save_cache(cache)  # Save updated cache

    return result

# Read each log file
for log_file in log_files:
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                log_entry = match.groupdict()

                src_ip = log_entry["src_ip"]
                dst_ip = log_entry["dst_ip"]
                
                # Add src/dest IP type (Private/Public)
                log_entry["src_type"] = get_ip_type(src_ip)
                log_entry["dst_type"] = get_ip_type(dst_ip)

                # Add src/dest IP description
                src_description = get_ip_description(src_ip)
                dst_description = get_ip_description(dst_ip)
                 
                if src_description == "Houzeau":
                    internal_ip = src_ip
                    external_ip = dst_ip
                elif dst_description == "Houzeau":
                    internal_ip = dst_ip
                    external_ip = src_ip

                log_entry["src_description"] = src_description
                log_entry["dst_description"] = dst_description

                log_entry["internal_ip"] = internal_ip
                log_entry["external_ip"] = external_ip

                parsed_logs.append(log_entry)


# Convert parsed logs to a Pandas DataFrame
df = pd.DataFrame(parsed_logs)


# Convert priority to integer for sorting
df["priority"] = df["priority"].astype(int)

# Convert timestamp to datetime format
df["timestamp"] = pd.to_datetime(df["timestamp"], format="%m/%d/%Y-%H:%M:%S.%f")

# If the message contains the mention a group number (e.g., "group 450"), remove the mention form the message
def clean_message(message):
    return re.sub(r'\bgroup \d+\b', '', message, flags=re.IGNORECASE).strip()

# Apply the function to clean the messages in the dataframe
df["message"] = df["message"].apply(clean_message)

# Group by classification to count occurrences
classification_counts = df["classification"].value_counts()

# Group by protocol
protocol_counts = df["protocol"].value_counts()

# Group by priority
priority_counts = df["priority"].value_counts().sort_index()

# Plot 6quater: Top 10 internal IP addresses with message color inside the bar (top 10 messages other grouped)
# Get the top 10 internal IPs
top_internal_ips = df["internal_ip"].value_counts().head(10).index

# Filter the dataset for only those top 10 internal IPs
df_filtered = df[df["internal_ip"].isin(top_internal_ips)].copy()

# Find the top 10 most frequent messages within this subset
top_messages_in_internal_ips = df_filtered["message"].value_counts().head(10).index

# Replace messages not in the top 10 with "Other"
df_filtered.loc[:, "message_filtered"] = df_filtered["message"].apply(lambda x: x if x in top_messages_in_internal_ips else "Other")

# Group by internal IP and filtered message counts
internal_ip_message_counts = (
    df_filtered.groupby(["internal_ip", "message_filtered"])
    .size()
    .unstack(fill_value=0)
)

# Sort by total count (for better visualization)
internal_ip_message_counts["total"] = internal_ip_message_counts.sum(axis=1)
internal_ip_message_counts = internal_ip_message_counts.sort_values(by="total", ascending=False).drop(columns="total")

# Plot stacked bar chart
internal_ip_message_counts.plot(kind="bar", stacked=True, figsize=(12, 6))
plt.xticks(rotation=45, ha="right")
plt.title("Top 10 Internal IPs with Message Distribution (Filtered)")
plt.xlabel("Internal IP Address")
plt.ylabel("Count")
plt.legend(title="Message", bbox_to_anchor=(1.05, 1), loc="upper left")
plt.tight_layout()
plt.show()


# Plot 7: Ip destination distribution
# ip_dest_counts = df["dst_ip"].value_counts().head(10)
# plt.figure(figsize=(10, 5))
# sns.barplot(x=ip_dest_counts.index, y=ip_dest_counts.values, palette="coolwarm")
# plt.xticks(rotation=45, ha="right")
# plt.title("Top 10 Destination IP Addresses")
# plt.xlabel("Destination IP Address")
# plt.ylabel("Count")
# plt.show()

# Plot 7bis: Top 10 external IP addresses
external_ip_counts = df["external_ip"].value_counts().head(10)
plt.figure(figsize=(10, 5))
sns.barplot(x=external_ip_counts.index, y=external_ip_counts.values)
plt.xticks(rotation=45, ha="right")
plt.title("Top 10 External IP Addresses")
plt.xlabel("External IP Address")
plt.ylabel("Count")
plt.show()


# Plot 8: Take the top 10 source IP addresses and top 10 destination IP addresses and plot a heatmap of the number of alerts between them
ip_source_counts = df["src_ip"].value_counts().head(10)
ip_dest_counts = df["dst_ip"].value_counts().head(10)
top_ips = ip_source_counts.index.union(ip_dest_counts.index)
ip_matrix = pd.DataFrame(index=top_ips, columns=top_ips, data=0)
for _, row in df.iterrows():
    src_ip = row["src_ip"]
    dst_ip = row["dst_ip"]
    if src_ip in top_ips and dst_ip in top_ips:
        ip_matrix.at[src_ip, dst_ip] += 1

plt.figure(figsize=(10, 10))
sns.heatmap(ip_matrix, cmap="coolwarm", annot=True, fmt="d")
plt.title("Alerts Between Top 10 Source and Destination IP Addresses")
plt.xlabel("Destination IP Address")
plt.ylabel("Source IP Address")
plt.show()

# Plot 8bis: Take the top 10 internal IP addresses and top 10 external IP addresses and plot a heatmap of the number of alerts between them
internal_ip_counts = df["internal_ip"].value_counts().head(10)
external_ip_counts = df["external_ip"].value_counts().head(10)
top_ips = internal_ip_counts.index.union(external_ip_counts.index)
ip_matrix = pd.DataFrame(index=top_ips, columns=top_ips, data=0)
for _, row in df.iterrows():
    internal_ip = row["internal_ip"]
    external_ip = row["external_ip"]
    if internal_ip in top_ips and external_ip in top_ips:
        ip_matrix.at[internal_ip, external_ip] += 1

plt.figure(figsize=(10, 10))
sns.heatmap(ip_matrix, cmap="coolwarm", annot=True, fmt="d")
plt.title("Alerts Between Top 10 Internal and External IP Addresses")
plt.xlabel("External IP Address")
plt.ylabel("Internal IP Address")
plt.show()

# Plot 9: Show correlation between priority and classification
priority_classification = df.groupby(["priority", "classification"]).size().unstack().fillna(0)
plt.figure(figsize=(12, 6))
sns.heatmap(priority_classification, cmap="coolwarm", annot=True)
plt.title("Priority vs Classification")
plt.xlabel("Classification")
plt.ylabel("Priority")
plt.show()

# Plot 10: Show correlation between priority and IP frequency (take the top 10 source IP addresses)
top_ips = ip_source_counts.index
priority_ip = df[df["src_ip"].isin(top_ips)].groupby(["priority", "src_ip"]).size().unstack().fillna(0)
plt.figure(figsize=(12, 6))
sns.heatmap(priority_ip, cmap="coolwarm", annot=True)
plt.title("Priority vs Source IP Address")
plt.xlabel("Source IP Address")
plt.ylabel("Priority")
plt.show()

# Plot 11: Show correlation between priority and IP frequency (take the top 10 destination IP addresses)
top_ips = ip_dest_counts.index
priority_ip = df[df["dst_ip"].isin(top_ips)].groupby(["priority", "dst_ip"]).size().unstack().fillna(0)
plt.figure(figsize=(12, 6))
sns.heatmap(priority_ip, cmap="coolwarm", annot=True)
plt.title("Priority vs Destination IP Address")
plt.xlabel("Destination IP Address")
plt.ylabel("Priority")
plt.show()

# Plot 12: Show correlation between classification and IP frequency (take the top 10 source IP addresses)
top_ips = ip_source_counts.index
classification_ip = df[df["src_ip"].isin(top_ips)].groupby(["classification", "src_ip"]).size().unstack().fillna(0)
plt.figure(figsize=(12, 6))
sns.heatmap(classification_ip, cmap="coolwarm", annot=True)
plt.title("Classification vs Source IP Address")
plt.xlabel("Source IP Address")
plt.ylabel("Classification")
plt.show()

# Plot 13: Show correlation between classification and IP frequency (take the top 10 destination IP addresses)
top_ips = ip_dest_counts.index
classification_ip = df[df["dst_ip"].isin(top_ips)].groupby(["classification", "dst_ip"]).size().unstack().fillna(0)
plt.figure(figsize=(12, 6))
sns.heatmap(classification_ip, cmap="coolwarm", annot=True)
plt.title("Classification vs Destination IP Address")
plt.xlabel("Destination IP Address")
plt.ylabel("Classification")
plt.show()









