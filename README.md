<h1>Failed RDP to IP Geolocation Information</h1>


 ### [YouTube Demonstration](https://www.youtube.com/watch?v=yU_YuGYtJGU)


<h2>Description</h2>
<b>The Powershell script in this repository is responsible for parsing out Windows Event Log information for failed RDP attacks and using a third party API to collect geographic information about the attackers location.
</b>
<br />
<br />
The script is used in this demo where I setup Azure Sentinel (SIEM) and connect it to a live virtual machine acting as a honey pot.
We will observe live attacks (RDP Brute Force) from all around the world. I will use a custom PowerShell script to
look up the attackers Geolocation information and plot it on an Azure Sentinel Map!
<br />
<br />

<h2>Languages Used</h2>

- <b>PowerShell:</b> Extract RDP failed logon logs from Windows Event Viewer 

<h2>Utilities Used</h2>

- <b>ipgeolocation.io:</b> IP Address to Geolocation API
- <b>Azure resource groups[VM, NSG, log analytics wrokspace]</b>
- <b>Azure Sentinel</b>

<h2>Network Design</h2>

<p align="center">
<img src="https://i.imgur.com/TGMwqFd.png" height="85%" width="85%" alt="Image Analysis Dataflow"/>
</p>

<h2>World map of incoming attacks after 14 hours (built custom logs including geodata)</h2>

<p align="center">
<img src="https://i.imgur.com/9Ozxzoa.png" height="85%" width="85%" alt="Image Analysis Dataflow"/>
</p>

<h2>PowerShell Code Explanation</h2>

1. **API Key and Log File Setup:**

   $API_KEY = "d4600b4efdef42b39828f5155041a457"
   $LOGFILE_NAME = "failed_rdp.log"
   $LOGFILE_PATH = "C:\ProgramData\$($LOGFILE_NAME)"

- `API_KEY`: This variable stores the API key obtained from "https://ipgeolocation.io/" to access their geolocation service.
- `LOGFILE_NAME`: The name of the log file.
- `LOGFILE_PATH`: The full path where the log file will be stored.

2. **XML Filter for Event Viewer:**
   
   $XMLFilter = @'
   <QueryList> 
       <Query Id="0" Path="Security">
           <Select Path="Security">
               *[System[(EventID='4625')]]
           </Select>
       </Query>
   </QueryList> 
   '@

- This XML filter is used to retrieve specific events from the Windows Event Viewer (Security log) with EventID '4625', which typically indicates failed RDP login attempts.

3. **Creating Sample Log Entries:**

   Function write-Sample-Log() {
       # ... (sample log entries for training purposes)
   }

- This function creates sample log entries that will be used to "train" the log analytics workspace's extraction feature.

4. **Checking and Creating Log File:**

   if ((Test-Path $LOGFILE_PATH) -eq $false) {
       New-Item -ItemType File -Path $LOGFILE_PATH
       write-Sample-Log
   }

- Checks if the log file exists. If not, it creates a new log file and writes sample log entries using the `write-Sample-Log` function.

5. **Infinite Loop to Monitor Event Viewer:**

   while ($true) {
       # ... (code inside the loop to continuously check Event Viewer)
   }

- This sets up an infinite loop to continuously check the Event Viewer for failed RDP login attempts.

6. **Event Processing:**

   foreach ($event in $events) {
       # ... (code to process each event and extract relevant information)
   }

- Processes each event retrieved from the Event Viewer, extracts relevant information such as timestamp, event ID, source and destination host, username, and source IP.

7. **Geolocation Retrieval and Logging:**
   
   if ($event.properties[19].Value.Length -ge 5) {
       # ... (code to retrieve geolocation based on IP address and log the information)
   }

- Checks if the event contains a valid source IP address, then uses the IP address to retrieve geolocation information using the "https://api.ipgeolocation.io/" API, and logs the relevant information.

This script continuously monitors failed RDP login attempts in the Windows Event Viewer, extracts relevant details, fetches geolocation information for the source IP addresses, and logs this information into a custom log file.

Of course! Here are the explanations with headlines for each part:

8. **Extracting Date and Time Components**

$month = $event.TimeCreated.Month
if ("$($event.TimeCreated.Month)".Length -eq 1) {
    $month = "0$($event.TimeCreated.Month)"
}

- Extracts the month from the event timestamp and ensures a two-digit representation.

9. **Formatting the Timestamp**

$timestamp = "$($year)-$($month)-$($day) $($hour):$($minute):$($second)"

- Constructs a timestamp in the format: "YYYY-MM-DD HH:MM:SS" using the extracted date and time components.

10. **Extracting Event Information**

$eventId = $event.Id
$destinationHost = $event.MachineName
$username = $event.properties[5].Value
$sourceHost = $event.properties[11].Value
$sourceIp = $event.properties[19].Value

- Extracts relevant information from the event, such as Event ID, destination host, username, source host, and source IP.

11. **Checking Log File and Timestamp**

$log_contents = Get-Content -Path $LOGFILE_PATH
if (-Not ($log_contents -match "$($timestamp)") -or ($log_contents.Length -eq 0)) {
    # ... (code inside this block)
}
else {
    # ... (code to handle when the entry already exists in the log file)
}

- Checks if the log entry with the current timestamp already exists or if the log file is empty.

12. **Processing Geolocation Data and Writing to Log file**
  Start-Sleep -Seconds 1

                # Make web request to the geolocation API
                # For more info: https://ipgeolocation.io/documentation/ip-geolocation-api.html
                $API_ENDPOINT = "https://api.ipgeolocation.io/ipgeo?apiKey=$($API_KEY)&ip=$($sourceIp)"
                $response = Invoke-WebRequest -UseBasicParsing -Uri $API_ENDPOINT

                # Pull Data from the API response, and store them in variables
                $responseData = $response.Content | ConvertFrom-Json
                $latitude = $responseData.latitude
                $longitude = $responseData.longitude
                $state_prov = $responseData.state_prov
                if ($state_prov -eq "") { $state_prov = "null" }
                $country = $responseData.country_name
                if ($country -eq "") {$country -eq "null"}

                # Write all gathered data to the custom log file. It will look something like this:
                #
                "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov), country:$($country),label:$($country) - $($sourceIp),timestamp:$($timestamp)" | Out-File $LOGFILE_PATH -Append -Encoding utf8

                Write-Host -BackgroundColor Black -ForegroundColor Magenta "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov),label:$($country) - $($sourceIp),timestamp:$($timestamp)"
            }

- Contains the code to retrieve geolocation data based on the source IP and process the retrieved information.
- Constructs a log entry with extracted event and geolocation information and writes it to the log file.

13. **Handling Existing Log Entry**

else {
    # ... (code to handle when the entry already exists in the log file)
}

- Contains code to handle the case when an entry with the current timestamp already exists in the log file. In this provided code, it's left empty and does nothing.
