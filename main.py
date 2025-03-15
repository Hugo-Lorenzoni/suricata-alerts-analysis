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
from concurrent.futures import ThreadPoolExecutor

from utils import wrap_labels
from datetime import datetime

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
    if ipaddress.ip_address(ip).is_multicast : return "Multicast"
    if ipaddress.ip_address(ip).is_global : return "Internet"
    else : return "Other"

def get_whois_info(ip):
    if ip in ipwhois_info and ipwhois_info[ip] and not ipwhois_info[ip].startswith("Unknown"):
        return

    if ip == "45.161.50.160" or ip == "45.185.17.41" or ip == "186.219.189.202":
        ipwhois_info[ip] = "Unknown"
        return
    
    try:
        print(f"Processing IP {ip}")
        obj = IPWhois(ip)
        result = obj.lookup_rdap()

        asn_description = result.get("asn_description")
        asn_country = result.get("asn_country_code")
        if asn_description: ipwhois_info[ip] = asn_description
        else:
            r = obj.lookup_whois(get_asn_description=False)
            asn_description = r.get("nets")[0].get("description")
            asn_country = r.get("nets")[0].get("country")
            asn_name = r.get("nets")[0].get("name")
            if asn_description and asn_country: 
                print(ip, f"{asn_description}, {asn_country}")
                ipwhois_info[ip] = f"{asn_description}, {asn_country}"
            elif asn_name and asn_country:
                print(ip, f"{asn_name}, {asn_country}")
                ipwhois_info[ip] = f"{asn_name}, {asn_country}"
            else:
                print(ip, r)
                ipwhois_info[ip] = f"Unknown, {asn_country}" if asn_country else "Unknown"
        
        # Save to cache
        with open(cache_file, "w") as f:
            json.dump(ipwhois_info, f)
    except Exception as e:
        print(f"Error processing IP {ip}: {e}")

# Speed up using ThreadPoolExecutor
def fetch_whois_parallel(ip_list, max_threads=10):
    with ThreadPoolExecutor(max_threads) as executor:
        executor.map(get_whois_info, ip_list)


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
                    internal_description = src_description
                    external_ip = dst_ip
                    external_description = dst_description
                elif dst_description == "Houzeau":
                    internal_ip = dst_ip
                    internal_description = dst_description
                    external_ip = src_ip
                    external_description = src_description
                else:
                    print("Error: Houzeau IP not found")
                    print(src_ip, dst_ip)

                log_entry["src_description"] = src_description
                log_entry["dst_description"] = dst_description

                log_entry["internal_ip"] = internal_ip
                log_entry["external_ip"] = external_ip

                log_entry["internal_description"] = internal_description
                log_entry["external_description"] = external_description

                parsed_logs.append(log_entry)

# Convert parsed logs to a Pandas DataFrame
df = pd.DataFrame(parsed_logs)

# Get the ipwhois information (asn description) for the "Internet" IP addresses 
internet_ips = df[df["external_description"] == "Internet"]["external_ip"].unique()
internet_ips = list(set(internet_ips))
total_ips = len(internet_ips)

ipwhois_info = {}

cache_file = "ipwhois_cache.json"

# Load cache if it exists
if os.path.exists(cache_file):
    with open(cache_file, "r") as f:
        ipwhois_info = json.load(f)
else:
    ipwhois_info = {}

# Run parallel WHOIS queries
fetch_whois_parallel(internet_ips)

# Replace the "Internet" description in the dataframe by the asn_description
def update_description(row):
    if row["dst_description"] == "Internet":
        row["external_description"] = ipwhois_info.get(row["external_ip"], "Unknown")
    elif row["src_description"] == "Internet":
        row["external_description"] = ipwhois_info.get(row["external_ip"], "Unknown")
    return row
df = df.apply(update_description, axis=1)

# print the line with the None external_description
print(df[df["external_description"].isnull()])

# Add a new column with the country code of the external IP (got from splitting the external_description and keeping the last part)
def extract_country(description):
    if description == "Routeur" or description == "UMONS":
        return "BE"
    try:
        country = description.split()[-1]
        return country
    except Exception:
        # print(description)
        return "Unknown"

df["external_country"] = df["external_description"].apply(extract_country)

def update_srcdst_description(row):
    if row["src_description"] == "Internet":
        row["src_description"] = ipwhois_info.get(row["src_ip"])
    if row["dst_description"] == "Internet":
        row["dst_description"] = ipwhois_info.get(row["dst_ip"])
    return row
df = df.apply(update_srcdst_description, axis=1)

# Convert priority to integer for sorting
df["priority"] = df["priority"].astype(int)

# Convert timestamp to datetime format
df["timestamp"] = pd.to_datetime(df["timestamp"], format="%m/%d/%Y-%H:%M:%S.%f")

# If the message contains the mention a group number (e.g., "group 450"), remove the mention form the message
def clean_message(message):
    return re.sub(r'\bgroup \d+\b', '', message, flags=re.IGNORECASE).strip()
df["message"] = df["message"].apply(clean_message)

# Display the first few rows of the DataFrame
print(df.head())

# Create a folder to store the figures named "date-time-figures"
figures_folder = datetime.now().strftime("%Y-%m-%d_%Hh%M_figures")
os.makedirs(figures_folder, exist_ok=True)

# Update the save path for figures
plt.savefig = lambda path, *args, **kwargs: plt.gcf().savefig(os.path.join(figures_folder, os.path.basename(path)), *args, **kwargs)

index = 1


# Plot: Alert Classifications with priority color inside the bar on a log scale
classification_priority_counts = df.groupby(["classification", "priority"]).size().unstack(fill_value=0)
classification_priority_counts["total"] = classification_priority_counts.sum(axis=1)
classification_priority_counts = classification_priority_counts.sort_values(by="total", ascending=False).drop(columns="total")
classification_priority_counts.plot(kind="bar", stacked=True, figsize=(16, 8), logy=True)
plt.xticks(rotation=45, ha="right")
plt.title("Alert Classifications with Priority Distribution (Log Scale)")
plt.xlabel("Classification")
plt.ylabel("Count") 
plt.legend(title="Priority", bbox_to_anchor=(1.05, 0.5), loc="center left")  # Move legend outside
plt.tight_layout()
plt.savefig(f"figures/figure_{index:02d}-alert_classifications.png")
plt.savefig(f"figures/figure_{index:02d}-alert_classifications.pdf")
plt.show()
index += 1

# Plot: Top 20 messages distribution for each classification
top_20_messages = df["message"].value_counts().head(20).index
df["message_grouped"] = df["message"].apply(lambda x: x if x in top_20_messages else "Other")
classification_message_counts = df.groupby(["classification", "message_grouped"]).size().unstack(fill_value=0)
classification_message_counts["total"] = classification_message_counts.sum(axis=1)
classification_message_counts = classification_message_counts.sort_values(by="total", ascending=False).drop(columns="total")
classification_message_counts.plot(kind="bar", stacked=True, figsize=(16, 8))
plt.xticks(rotation=45, ha="right")
plt.title("Top 20 Alert Messages Distribution by Classification (Others Grouped)")
plt.xlabel("Classification")
plt.ylabel("Count")
plt.legend(title="Message", bbox_to_anchor=(1.05, 0.5), loc="center left")
plt.tight_layout()
plt.savefig(f"figures/figure_{index:02d}-top_20_messages.png")
plt.savefig(f"figures/figure_{index:02d}-top_20_messages.pdf")
plt.show()
index += 1

# Plots: (for each classification) Pie distribution of messages
classification_counts = df["classification"].value_counts()
for classification in classification_counts.index:
    messages = df[df["classification"] == classification]["message"].value_counts(normalize=True) * 100
    messages = messages.sort_values(ascending=False)
    
    # Group messages from the 9th onward into "Other"
    if len(messages) > 9:
        other_percentage = messages.iloc[9:].sum()
        messages = messages.iloc[:9]
        messages["Other"] = other_percentage
    
    plt.figure(figsize=(16, 8))
    plt.pie(messages, labels=None, autopct="%1.1f%%", startangle=140)
    plt.title(f"Alert message distribution for {classification} (Priority {df[df['classification'] == classification]['priority'].iloc[0]})")
    plt.legend(labels=wrap_labels(messages.index), loc="center left", bbox_to_anchor=(1.05, 0.5))
    plt.tight_layout()
    plt.subplots_adjust(left=0, right=0.75)
    plt.savefig(f"figures/figure_{index:02d}-alert_message_distribution_{classification}.png")
    plt.savefig(f"figures/figure_{index:02d}-alert_message_distribution_{classification}.pdf")
    plt.show()
    index += 1

# Plots: (for each classification) Pie distribution of external IP descriptions
classification_counts = df["classification"].value_counts()
for classification in classification_counts.index:
    descriptions = df[df["classification"] == classification]["external_description"].value_counts(normalize=True) * 100
    descriptions = descriptions.sort_values(ascending=False)
    
    # Group descriptions from the 9th onward into "Other"
    if len(descriptions) > 9:
        other_percentage = descriptions.iloc[9:].sum()
        descriptions = descriptions.iloc[:9]
        descriptions["Other"] = other_percentage
    
    plt.figure(figsize=(16, 8))
    plt.pie(descriptions, labels=None, autopct="%1.1f%%", startangle=140)
    plt.title(f"External IP description distribution for {classification} (Priority {df[df['classification'] == classification]['priority'].iloc[0]})")
    plt.legend(labels=wrap_labels(descriptions.index), loc="center left", bbox_to_anchor=(1.05, 0.5))
    plt.tight_layout()
    plt.subplots_adjust(left=0, right=0.75)
    plt.savefig(f"figures/figure_{index:02d}-external_ip_description_{classification}.png")
    plt.savefig(f"figures/figure_{index:02d}-external_ip_description_{classification}.pdf")
    plt.show()
    index += 1

# Plot: Top 10 internal IP addresses with classification color inside the bar
internal_ip_counts = df["internal_ip"].value_counts().head(10)
internal_ip_classification_counts = df[df["internal_ip"].isin(internal_ip_counts.index)].groupby(["internal_ip", "classification"]).size().unstack(fill_value=0)
internal_ip_classification_counts["total"] = internal_ip_classification_counts.sum(axis=1)
internal_ip_classification_counts = internal_ip_classification_counts.sort_values(by="total", ascending=False).drop(columns="total")
internal_ip_classification_counts.plot(kind="bar", stacked=True, figsize=(12, 6))
plt.xticks(rotation=45, ha="right")
plt.title("Top 10 Internal IP Addresses with Classification Distribution")
plt.xlabel("Internal IP Address")
plt.ylabel("Count")
plt.legend(title="Classification", bbox_to_anchor=(1.05, 1), loc="upper left")
plt.tight_layout()
plt.savefig(f"figures/figure_{index:02d}-top_10_internal_ip_classification.png")
plt.savefig(f"figures/figure_{index:02d}-top_10_internal_ip_classification.pdf")
plt.show()
index += 1

# Plot: Top 10 internal IP addresses with message color inside the bar (top 10 messages other grouped)
top_internal_ips = df["internal_ip"].value_counts().head(10).index
df_filtered = df[df["internal_ip"].isin(top_internal_ips)].copy()
top_messages_in_internal_ips = df_filtered["message"].value_counts().head(9).index
df_filtered.loc[:, "message_filtered"] = df_filtered["message"].apply(lambda x: x if x in top_messages_in_internal_ips else "Other")
internal_ip_message_counts = (
    df_filtered.groupby(["internal_ip", "message_filtered"])
    .size()
    .unstack(fill_value=0)
)
internal_ip_message_counts["total"] = internal_ip_message_counts.sum(axis=1)
internal_ip_message_counts = internal_ip_message_counts.sort_values(by="total", ascending=False).drop(columns="total")
internal_ip_message_counts.plot(kind="bar", stacked=True, figsize=(12, 6))
plt.xticks(rotation=45, ha="right")
plt.title("Top 10 Internal IPs with Message Distribution (Filtered)")
plt.xlabel("Internal IP Address")
plt.ylabel("Count")
plt.legend(title="Message", bbox_to_anchor=(1.05, 1), loc="upper left")
plt.tight_layout()
plt.savefig(f"figures/figure_{index:02d}-top_10_internal_ip_message_filtered.png")
plt.savefig(f"figures/figure_{index:02d}-top_10_internal_ip_message_filtered.pdf")
plt.show()
index += 1


# Plot: (for each classification) Heatmap heatmap of top 10 internal IPs and external descriptions
classification_counts = df["classification"].value_counts()
for classification in classification_counts.index:
    top_internal_ips = df[df["classification"] == classification]["internal_ip"].value_counts().head(10).index
    df_filtered = df[df["internal_ip"].isin(top_internal_ips) & (df["classification"] == classification)].copy()
    top_external_descriptions = df_filtered["external_description"].value_counts().head(10).index
    df_filtered = df_filtered[df_filtered["external_description"].isin(top_external_descriptions)]
    external_description_counts = df_filtered.groupby(["internal_ip", "external_description"]).size().unstack(fill_value=0).T
    external_description_counts = external_description_counts.reindex(sorted(external_description_counts.columns), axis=1)
    
    plt.figure(figsize=(12, 6))
    sns.heatmap(external_description_counts, annot=True, fmt="d", cmap="Blues")
    plt.title(f"Top 10 Internal IPs and External Descriptions for {classification} (Priority {df[df['classification'] == classification]['priority'].iloc[0]})")
    plt.xlabel("Internal IP Address")
    plt.ylabel("External Description")
    plt.tight_layout()
    plt.savefig(f"figures/figure_{index:02d}-top_10_internal_ip_external_description_{classification}.png")
    plt.savefig(f"figures/figure_{index:02d}-top_10_internal_ip_external_description_{classification}.pdf")
    plt.show()
    index += 1


# Plot: (for top 5 country codes) Heatmap of the classification and top 10 external descriptions
top_country_codes = df["external_country"].value_counts().head(5).index
for country_code in top_country_codes:
    top_external_descriptions = df[df["external_country"] == country_code]["external_description"].value_counts().head(10).index
    df_filtered = df[df["external_country"] == country_code].copy()
    df_filtered = df_filtered[df_filtered["external_description"].isin(top_external_descriptions)]
    external_description_counts = df_filtered.groupby(["classification", "external_description"]).size().unstack(fill_value=0).T
    external_description_counts = external_description_counts.reindex(sorted(external_description_counts.columns), axis=1)
    
    plt.figure(figsize=(12, 6))
    sns.heatmap(external_description_counts, annot=True, fmt="d", cmap="Blues")
    plt.title(f"Top 10 External Descriptions and Alert Classifications Correlation Matrix for {country_code}")
    plt.xlabel("Classification")
    plt.ylabel("External Description")
    plt.tight_layout()
    plt.savefig(f"figures/figure_{index:02d}-alert_classifications_top_10_external_description_{country_code}.png")
    plt.savefig(f"figures/figure_{index:02d}-alert_classifications_top_10_external_description{country_code}.pdf")
    plt.show()
    index += 1