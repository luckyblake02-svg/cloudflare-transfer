<#
This function was originally written by JDM. I've tweaked it to fit the needs of this script. 
It reaches out to DNSimple via API call and for each domain name in a given list, retrieves the dns zone file associated with it and stores it to it's own file.
It then performs two separate regex match operations to change the syntax from DNSimple to Cloudflare, and another to split URL records into their own file for later processing.
#>
function get-dnszone {
    #Set security to TLS1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    #Set password vault fields for data retrieval
    $username = "<USERNAME>"
    $uri = "<passwordVaultAPIURL>"
    $body = @{
        grant_type = 'password'
        username   = $username
        password   = "<password>"
    }

    Write-Host "Grabbing password vault access token..."
    #Grab secret password vault token
    $response = invoke-restmethod -method post -uri $uri -body $body -headers $null
    $token = $response | select -expand access_token

    $header = @{ "Authorization" = "Bearer $token" }
    $pwsurl = "<passwordVaultSecretURL>"
    Write-Host "Requesting dnsimple account info from password vault..."
    
    try{
        #Using token, get actual token and account information.
        $response = Invoke-Restmethod -Method GET -Uri $PwsUrl -Header $header

        $AccessToken = $response.items | ? { $_.fieldname -eq "Password" } | select -expand itemvalue
        $dnsaccount = $response.items | ? { $_.fieldname -eq "Username" } | select -expand itemvalue
    }
    catch {Write-Host "DNSimple information request failed." ; exit 0}

    Write-Host "Getting DNSimple DNS Zones!"
    $file = (Get-Content "C:\Users\$env:username\Downloads\domainList.txt")
    foreach ($domain in $file) {
        try {
            #HTTP GET request for domain zone file.
            $store = (Invoke-RestMethod -Headers @{Authorization = "Bearer $AccessToken"} "https://api.dnsimple.com/v2/$dnsaccount/zones/$domain/file").data.zone 
            $store | Out-File "C:\Users\$env:username\Downloads\dnsimple\$domain.txt"
            Write-Host "Got the zone for $domain!"
        } 
        catch {Write-Host "API request for domain zone list for $domain failed."}
        $check = (Get-Content "C:\Users\$env:username\Downloads\dnsimple\$domain.txt")
        Write-Host "Matching regex on certain characters in $domain's zone file to fix import." 
        #Will check for leading ; 0-1 times. Then any characters followed by . Match any number 2-4 times. Match "IN " then either CNAME, ALIAS, or URL.
        $pattern = '((; )?((\S*\. [0-9]{2,4} IN )(CNAME)?(ALIAS)?(URL)?))'
        #Replace entire matched line with 3rd match group (everything but ;) Replace ALIAS with CNAME, URL with URI. For Cloudflare syntax.
        ($check -replace $pattern, "`$3" -replace "IN ALIAS", "IN CNAME" -replace "URL", "URI" | Set-Content -Path "C:\Users\$env:username\Downloads\dnsimple\$domain.txt")     
    }
    foreach ($domain in $file) {
        #Match any characters followed by . Then any digit 2-4 times. Followed by IN URI and any characters. Matches only URI record strings.
        $pattern2 = '(\S*\. [0-9]{2,4} IN URI \S*)'
        $check = (Get-Content "C:\Users\$env:username\Downloads\dnsimple\$domain.txt")
        #Select all matches to pattern and store in $split.
        $split = $check | Select-String -Pattern $pattern2 -AllMatches
        foreach ($item in $split.Matches) {
            #Store each matched line in a new file marked with 'URI'.
            $item.Value | Out-File -Append "C:\Users\$env:username\Downloads\dnsimple\$domain'URI'.txt"
        }
        #Replace match in original file with blank line.
        $check -replace $pattern2, "" | Set-Content -Path "C:\Users\$env:username\Downloads\dnsimple\$domain.txt"
        Write-Host "Splitting $domain's URI records into a new file."
    }
}

<#
Initialize cloudflare credentials. This was stored into it's own function due to the nature of the beginning of code execution, where you can utilize 2 separate cloudflare options.
Also sets 3 global variables for the import-again function.
Credentials are accessed using password vault API calls, as well as locally-stored environment variables in order to mask username fields.
#>
function initialize-creds {

    Write-Host "

.___       .__  __  .__       .__  .__       .__                 _________                    .___      
|   | ____ |__|/  |_|__|____  |  | |__|______|__| ____    ____   \_   ___ \_______   ____   __| _/______
|   |/    \|  \   __\  \__  \ |  | |  \___   /  |/    \  / ___\  /    \  \/\_  __ \_/ __ \ / __ |/  ___/
|   |   |  \  ||  | |  |/ __ \|  |_|  |/    /|  |   |  \/ /_/  > \     \____|  | \/\  ___// /_/ |\___ \ 
|___|___|  /__||__| |__(____  /____/__/_____ \__|___|  /\___  /   \______  /|__|    \___  >____ /____  >
         \/                 \/              \/       \//_____/           \/             \/     \/    \/ 

    "
    #Import-again read in file
    $global:path = "C:\Users\$env:username\Downloads\RedoNameServ.txt"
    #Variable to tell import-again how many times it is going to actually "import again".
    $global:ct = Get-Content -Path $path | Measure-Object -Line
    #Keeps count of current line during execution of import-again.
    $global:L = 1

    #Set security to TLS1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    #Set password vault fields for data retrieval
    $username = "<username>"
    $uri = "<passwordVaultAPIURL>"
    $body = @{
        grant_type = 'password'
        username   = $username
        password   = "<password>"
    }

    Write-Host "Grabbing password vault access token..."
    #Grab password vault access token
    $response = invoke-restmethod -method post -uri $uri -body $body -headers $null
    $token = $response | select -expand access_token

    $header = @{ "Authorization" = "Bearer $token" }
    $pwsurl = "<passwordVaultSecretURL>"
    $pwsurl2 = "<passwordVaultSecretURL>"
    Write-Host "Requesting cloudflare account info from password vault, then CSC info..."
    
    try{
        #Using token, get actual token and account information.
        $response = Invoke-Restmethod -Method GET -Uri $PwsUrl -Header $header

        $global:token = $response.items | ? { $_.fieldname -eq "Password" } | select -expand itemvalue
        $global:account = $response.items | ? { $_.fieldname -eq "Username" } | select -expand itemvalue
    }
    catch {Write-Host "Cloudflare information request failed." ; exit 0}

    try{
        #Using token, get actual token and account information.
        $response = Invoke-Restmethod -Method GET -Uri $pwsurl2 -Header $header

        $global:key = $response.items | ? { $_.fieldname -eq "Password" } | select -expand itemvalue
        $global:cscToken = $response.items | ? { $_.fieldname -eq "Username" } | select -expand itemvalue
    }
    catch {Write-Host "CSC information request failed." ; exit 0}
    

    #Set to admin email address in cloudflare.
    $global:email = Read-Host "Please enter your email address for Cloudflare"

    Write-Host "Account and Token info stored!"

    #Global counter that actually never got used :P
    $global:i = 0

    #Create an array for cloudflare API request body.
    $global:info = @{
    "account" = @{
        "id" = "$account"
    }
    "name" = ""
    "type" = "full"
    }
}

<#
This is the actual bread and butter of the script. This sends the actual API request out to cloudflare to add a new domain. Once done, it will extract the assigned name servers and store them in a separate file.
This will also monitor for and catch an HTTP 429 error. API call limit reached. Only occurs if your name server changes are not populating faster than you are adding new domains.
#>
function addDomain {
    
    Write-Host "
       _____       .___  .___.__                     .___                    .__                  __           _________ .__                   .___ _____.__                        
      /  _  \    __| _/__| _/|__| ____    ____     __| _/____   _____ _____  |__| ____   ______ _/  |_  ____   \_   ___ \|  |   ____  __ __  __| _// ____\  | _____ _______   ____  
     /  /_\  \  / __ |/ __ | |  |/    \  / ___\   / __ |/  _ \ /     \\__  \ |  |/    \ /  ___/ \   __\/  _ \  /    \  \/|  |  /  _ \|  |  \/ __ |\   __\|  | \__  \\_  __ \_/ __ \ 
    /    |    \/ /_/ / /_/ | |  |   |  \/ /_/  > / /_/ (  <_> )  Y Y  \/ __ \|  |   |  \\___ \   |  | (  <_> ) \     \___|  |_(  <_> )  |  / /_/ | |  |  |  |__/ __ \|  | \/\  ___/ 
    \____|__  /\____ \____ | |__|___|  /\___  /  \____ |\____/|__|_|  (____  /__|___|  /____  >  |__|  \____/   \______  /____/\____/|____/\____ | |__|  |____(____  /__|    \___  >
            \/      \/    \/         \//_____/        \/            \/     \/        \/     \/                         \/                       \/                 \/            \/ 
    "
    if (Test-Path "C:\Users\$env:username\Downloads\domainList.txt") {
    $list = Get-Content -Path "C:\Users\$env:username\Downloads\domainList.txt"
    Write-Host "Got the list!"
    }
    else { Write-Host "Please ensure that domainList.txt is in the Downloads folder" }

    foreach ($global:domain in $list) {
    Write-Host "Adding $domain...`n"
    $info.name = "$domain"
    $info = convertto-json $info
    try {
        #HTTP POST request to cloudflare API to add a new domain.
        $addDomain = (Invoke-WebRequest -Headers @{"X-Auth-Email"="$email";"X-Auth-Key"="$token" } "https://api.cloudflare.com/client/v4/zones/" -Method Post -Body $info -ContentType "application/json")
    } 
    catch {
        #Only triggers if you max out your API request limit. This is an ever-changing number between 10-15 domains that are added without NS changes. Cloudflare doesn't like an abundance of them.
        if ($_.Exception.Response.StatusCode -eq 429) {
                Write-Host "Hit the API Rate Limit on $domain. Please configure the new domains in Cloudflare, then try again."
        }
        else {
            throw _.Exception
        }
    }
    $info = ConvertFrom-Json $info

    #Take a breather in order to not pummel the API request limit.
    Write-Output "Sleeping for 15 seconds to avoid API rate limit`n"; Start-Sleep 15

    Write-Host "Matching regex on nameservers and outputting to Downloads folder."
    #Regex match to extract the designated name servers from the "new" domain.
    $pattern = '("[a-z]*\.ns\.cloudflare\.com","[a-z]*\.ns\.cloudflare\.com")' 
    $match = [regex]::Match($addDomain, $pattern) 
    $part = $match.value
    #Output the nameservers to their own file for later.
    $part | Out-File "C:\Users\$env:username\Downloads\nameservers.txt"

    Write-Host "Calling CSC function..." ; csc_NS -dnsZone $domain
    #This is tracking something...
    $i++
    }
}

<#
This function calls out to the domain registrar (CSC) to perform a name server modification for the given domain.
Name servers are split into 2 pieces (1 per name server). Then uploaded to CSC.
#>
function csc_NS {
    #This was made prior to making $domain a global variable.
    param (
        $dnsZone
    )

    Write-Host "  

_________ .__                  .__                 _________   __________________   __________                              .___      
\_   ___ \|  |__ _____    ____ |__| ____    ____   \_   ___ \ /   _____/\_   ___ \  \______   \ ____   ____  ___________  __| _/______
/    \  \/|  |  \\__  \  /    \|  |/    \  / ___\  /    \  \/ \_____  \ /    \  \/   |       _// __ \_/ ___\/  _ \_  __ \/ __ |/  ___/
\     \___|   Y  \/ __ \|   |  \  |   |  \/ /_/  > \     \____/        \\     \____  |    |   \  ___/\  \__(  <_> )  | \/ /_/ |\___ \ 
 \______  /___|  (____  /___|  /__|___|  /\___  /   \______  /_______  / \______  /  |____|_  /\___  >\___  >____/|__|  \____ /____  >
        \/     \/     \/     \/        \//_____/           \/        \/         \/          \/     \/     \/                 \/    \/ 

    "

    $nameSrv = Get-content -Path "C:\Users\$env:username\Downloads\nameservers.txt"
    #Replace double quotes with nothing, for parsing. Split records by ','.
    $nameSrv = $nameSrv -replace """", ""
    $nameSrv = $nameSrv.Split(",")

    #Store each separate record in it's own variable.
    $ns1 = $nameSrv[0]
    $ns2 = $nameSrv[1]

    #Request body for CSC Domain Manager API.
    $body = [ordered]@{
        "qualifiedDomainName" = "$dnsZone"
        "nameServers" = @("$ns1","$ns2")
        "dnsType" = "OTHER_DNS"
        "notifications" = [ordered]@{
            "enabled" = "true"
            "additionalNotificationEmails" = @("<email1>","<email2>")
        }
        "showPrice" = "true"
        "customFields" = @()
    }

    $body = ConvertTo-Json $body

    try{
        #Curl PUT request for NS modification.
        $nsSwap = curl.exe -s -X PUT "https://apis.cscglobal.com/dbs/api/v2/domains/nsmodification" `
                  -H "Authorization: Bearer $cscToken" `
                  -H "apikey: $key" `
                  -H "Accept: application/json" `
                  -H "Content-Type: application/json" `
                  -d "$body"
        Write-Host $nsSwap
    } 
    catch {Write-Host "API Request to switch NS records at CSC failed."}
    
    Write-Host "Sleeping for 15 Seconds and moving to importZones!" ; Start-Sleep 15

    importZones
}

<#
This function only runs if prompted to by the user at start time. It reads from a redo file generated by standard domain creation failing.
For each domain in the redo file, it will re-attempt modifying NS records and page rules. If successful, the domain is removed from the file.
#>
function import-again {
    #Should've done a foreach loop, but this was originally a minimum viable product build to get things moving along.
    $domain = Get-Content -Path $path | Where-Object -Property ReadCount -eq $L
    Write-Host "We are going to try modifying NS records for $domain now" ; importZones
}

<#
This function actually takes the zone files from DNSimple and uploads them to Cloudflare.
For any URI records, a page ruleset and rules will be created, as Cloudflare does not process URI records anymore.
#>
function importZones {
    Write-Host "
     ____ ___        .__                    .___.__                 __________                              __           _________ .__                   .___ _____.__                        
    |    |   \______ |  |   _________     __| _/|__| ____    ____   \____    /____   ____   ____   ______ _/  |_  ____   \_   ___ \|  |   ____  __ __  __| _// ____\  | _____ _______   ____  
    |    |   /\____ \|  |  /  _ \__  \   / __ | |  |/    \  / ___\    /     //  _ \ /    \_/ __ \ /  ___/ \   __\/  _ \  /    \  \/|  |  /  _ \|  |  \/ __ |\   __\|  | \__  \\_  __ \_/ __ \ 
    |    |  / |  |_> >  |_(  <_> ) __ \_/ /_/ | |  |   |  \/ /_/  >  /     /(  <_> )   |  \  ___/ \___ \   |  | (  <_> ) \     \___|  |_(  <_> )  |  / /_/ | |  |  |  |__/ __ \|  | \/\  ___/ 
    |______/  |   __/|____/\____(____  /\____ | |__|___|  /\___  /  /_______ \____/|___|  /\___  >____  >  |__|  \____/   \______  /____/\____/|____/\____ | |__|  |____(____  /__|    \___  >
              |__|                   \/      \/         \//_____/           \/          \/     \/     \/                         \/                       \/                 \/            \/ 
    "

    #Set url base, as well as 2 counters for later.
    $url = 'https://api.cloudflare.com/client/v4/zones'
    $j = -1
    $p = 1 

    #$f tracks retries for NS modification. If you're redoing a domain, no need to try it 3 times. Try it once and move on.
    if ((Get-Content $path) -contains $domain) {
        $f = 2
    }
    else {
        #If the domain is not in the redo file.
        $f = 0
    }

    #$j changes to the index of the array where the domain is located. Since it is an array, 0 is a valid index. Use -1. $f tracks how many times we've tried it. Give it 3 good tries and move on.
    while ($j -eq -1 -and $f -lt 3) {
        try {
            Write-Host "Grabbing the zone list from Cloudflare..."
            #API Request to cloudflare for list of current domain entries. When a new domain is added, it should replicate here within minutes. 50 results per page, use $p as page counter once you exceed 50 domains.
            $zoneGrab = Invoke-WebRequest -Headers @{"X-Auth-Email"="$email";"X-Auth-Key"="$token" } -Uri "https://api.cloudflare.com/client/v4/zones?per_page=50&page=$p"
        } 
        catch { Write-Host "API Call for master zone list failed." ; exit 0}

        Write-Host "Converting the list from JSON..."
        $parseZone = convertfrom-json $zoneGrab
        $pM = [System.Math]::Ceiling(($parseZone.result_info.total_count) / 50)
        $parseZone | Select-Object -ExpandProperty result | Out-File "C:\Users\$env:username\Downloads\api.txt"
    
        #If the domain is on the file, set $j to it's index.
        $j = [array]::IndexOf($parseZone.result.name, "$domain")

        while ($j -eq -1 -and $p -le $pM) {
            #Check the next page just in case that's where the domain is.
            Write-Host "Domain does not exist on the api file yet. Checking the next page."
            $p++
            $zoneGrab = Invoke-WebRequest -Headers @{"X-Auth-Email"="$email";"X-Auth-Key"="$token" } "https://api.cloudflare.com/client/v4/zones?per_page=50&page=$p" ; $parseZone = convertfrom-json $zoneGrab
            $parseZone | Select-Object -ExpandProperty result | Out-File "C:\Users\$env:username\Downloads\api.txt"
            $j = [array]::IndexOf($parseZone.result.name, "$domain")
        }
        $f++
    }

    #If successful, $j maps to an index.
    if ($j -ne -1) {

        #Zone ID is a unique string cloudflare sets to identify a domain. Zone name is the domain name.
        $zoneID = $parseZone.result[$j].id
        $zoneName = $parseZone.result[$j].name

        if (Test-Path "C:\Users\$env:username\Downloads\dnsimple\$zoneName.txt") {
            $recordFile = "C:\Users\$env:username\Downloads\dnsimple\$zoneName.txt"
            Write-Host "Got the zone records for $domain!"
        }
        else { Write-Host "C:\Users\$env:username\Downloads\dnsimple\$zoneName.txt appears to not exist. Please ensure the file is present."}
        
        #If a URI file exists for the given domain.
        if (Test-Path "C:\Users\$env:username\Downloads\dnsimple\$domain'URI'.txt") {
            Write-Host "It appears there were URI records in the zone file. We are going to create some url forwarding rules for $domain."
            $content = Get-content "C:\Users\$env:username\Downloads\dnsimple\$domain'URI'.txt"
            $headers = @{'X-Auth-Email'= "$email"; 'X-Auth-Key'= "$token"}
            $uri = "$url/$zoneID/dns_records"
            #Regex match using 2 capturing groups and 6 non-capturing to get the source and destination address in their own capture.
            $regexpattern = "((?:w{3}\.)?(?:store\.)?(?:commercial\.)?[a-z]*[-]?[a-z]*(?:\.com\.)?(?:\.net\.)?(?:\.org\.)?) [0-9].* http(.*)"
            #$redirect is set to however many PSCustomObjects are created. 2 URL forwarders = 2 records.
            $z = 0
            $redirect = foreach ($src in $content) {
                $src -match $regexpattern | out-null
                if ($? -eq $true) {
                    [PSCustomObject]@{
                        #Set source and destination URL into their own objects.
                        origin = $matches[1].Trim(".")
                        dest   = 'http' + $matches[2]
                    }
                }
            }
            #If there is only 1 URI record (it messes with indexing)
            if ($redirect.count -eq 1) {
                $singleRec = $redirect.origin
                $singleDest = $redirect.dest
                #Set flag for later www rule creation.
                $flag = 0
                #Create CNAME record to point www to root.
                if ($singleRec -eq "www.$domain") {
                    $recordObj = @{
                        name    = $singleRec
                        ttl     = 1
                        type    = "CNAME"
                        content = $domain
                        proxied = $true
                    }
                    $params = @{
                    ContentType = 'application/json'
                        Headers = $headers
                        Body = $recordObj | ConvertTo-Json
                    }
                    $response = Invoke-WebRequest -Method Post -Uri $uri @params
                    Write-Host $response
                }
                #Create A record for store to trigger page rule.
                elseif ($singleRec -eq "store.$domain") {
                    $recordObj = @{
                        name    = $singleRec
                        ttl     = 1
                        type    = "A"
                        content = "192.0.2.1"
                        proxied = $true
                    }
                    $params = @{
                    ContentType = 'application/json'
                        Headers = $headers
                        Body = $recordObj | ConvertTo-Json
                    }
                    $response = Invoke-WebRequest -Method Post -Uri $uri @params
                    Write-Host $response
                }
                #Create A record for commercial to trigger page rule.
                elseif ($singleRec -eq "commercial.$domain") {
                    $recordObj = @{
                        name    = $singleRec
                        ttl     = 1
                        type    = "A"
                        content = "192.0.2.1"
                        proxied = $true
                    }
                    $params = @{
                    ContentType = 'application/json'
                        Headers = $headers
                        Body = $recordObj | ConvertTo-Json
                    }
                    $response = Invoke-WebRequest -Method Post-Uri $uri @params
                    Write-Host $response
                }
                elseif ($singleRec -eq "$domain") {
                    $recordObj = @{
                        name    = $singleRec
                        ttl     = 1
                        type    = "A"
                        content = "192.0.2.1"
                        proxied = $true
                    }
                    $params = @{
                        ContentType = 'application/json'
                        Headers = $headers
                        Body = $recordObj | ConvertTo-Json
                    }
                    $response = Invoke-WebRequest -Method Post -Uri $uri @params
                    Write-Host $response

                    #Create www default record as well
                    $recordObj = @{
                        name    = "www.$domain"
                        ttl     = 1
                        type    = "CNAME"
                        content = $domain
                        proxied = $true
                    }
                    $params = @{
                        ContentType = 'application/json'
                        Headers = $headers
                        Body = $recordObj | ConvertTo-Json
                    }
                    $response = Invoke-WebRequest -Method Post -Uri $uri @params
                    Write-Host $response
                }
                else {
                    Write-Host "Something went wrong trying to add records for $domain." ; exit 0
                }
            }
            elseif ($redirect.count -gt 1) {
                $flag = 1
                foreach ($src in $content) {
                    #Create CNAME record to point www to root.
                    if ($redirect.origin[$z] -eq "www.$domain") {
                        $recordObj = @{
                            name    = $redirect.origin[$z]
                            ttl     = 1
                            type    = "CNAME"
                            content = $domain
                            proxied = $true
                        }
                        $params = @{
                            ContentType = 'application/json'
                            Headers = $headers
                            Body = $recordObj | ConvertTo-Json
                        }
                        $response = Invoke-WebRequest -Method Post -Uri $uri @params
                        Write-Host $response
                    }
                    #Create A record for store to trigger page rule.
                    elseif ($redirect.origin[$z] -eq "store.$domain") {
                        $recordObj = @{
                            name    = $redirect.origin[$z]
                            ttl     = 1
                            type    = "A"
                            content = "192.0.2.1"
                            proxied = $true
                        }
                        $params = @{
                            ContentType = 'application/json'
                            Headers = $headers
                            Body = $recordObj | ConvertTo-Json
                        }
                        $response = Invoke-WebRequest -Method Post -Uri $uri @params
                        Write-Host $response
                    }
                    #Create A record for commercial to trigger page rule.
                    elseif ($redirect.origin[$z] -eq "commercial.$domain") {
                        $recordObj = @{
                            name    = $redirect.origin[$z]
                            ttl     = 1
                            type    = "A"
                            content = "192.0.2.1"
                            proxied = $true
                        }
                        $params = @{
                            ContentType = 'application/json'
                            Headers = $headers
                            Body = $recordObj | ConvertTo-Json
                        }
                        $response = Invoke-WebRequest -Method Post-Uri $uri @params
                        Write-Host $response
                    }
                    elseif ($redirect.origin[$z] -eq "$domain") {
                        $recordObj = @{
                            name    = $redirect.origin[$z]
                            ttl     = 1
                            type    = "A"
                            content = "192.0.2.1"
                            proxied = $true
                        }
                        $params = @{
                            ContentType = 'application/json'
                            Headers = $headers
                            Body = $recordObj | ConvertTo-Json
                        }
                        $response = Invoke-WebRequest -Method Post -Uri $uri @params
                        Write-Host $response
                    }
                    else {
                        Write-Host "Something went wrong trying to add records for $domain." ; exit 0
                    } 
                $z++
                }
                if ($content -notcontains "www.$domain") {
                    #Create www default record as well
                    $recordObj = @{
                        name    = "www.$domain"
                        ttl     = 1
                        type    = "CNAME"
                        content = $domain
                        proxied = $true
                    }
                    $params = @{
                        ContentType = 'application/json'
                        Headers = $headers
                        Body = $recordObj | ConvertTo-Json
                    }
                    $response = Invoke-WebRequest -Method Post -Uri $uri @params
                    Write-Host $response
                }
            }

            #This is just to save typing later.
            $rulePhase ="http_request_dynamic_redirect"
            #Curl GET to see if a ruleset exists for the given domain.
            $testPhase = curl.exe -s "$url/$zoneID/rulesets" `
                        -H "X-Auth-Email: $email" `
                        -H "X-Auth-Key: $token"
            $testPhase = $testPhase | ConvertFrom-Json
            if ($testPhase.success -match "false") {
                $errMsg = $testPhase.errors.message
                Write-Host "Curl request failed with error: $errMsg" ; exit 0
            }
            else {
                Write-Host "Curl request for ruleset list was successful!"
                #Static Redirect Ruleset is a custom name set for all my rulesets. Cloudflare auto generates their own, so you need to check if your's exists.
                $customRuleset = $testPhase.result | Where-Object name -like "Static Redirect Ruleset"
                #Store ruleset ID for later.
                $rulesetID = $customRuleset.id
                #If the ruleset does not exist.
                if (!$customRuleset) {
                    Write-Host "Custom Ruleset not found. We will create one."
                    $rulesUrl = "$url/$zoneID/rulesets"
                    #Create body for the ruleset. Rules are not added here, so the array is left empty.
                    $ruleBody = [ordered]@{
                        name = "Static Redirect Ruleset"
                        kind = "zone"
                        phase = "$rulePhase"
                        rules = @()
                    } | ConvertTo-Json

                    #HTTP POST request to create ruleset.
                    $ruleResponse = Invoke-RestMethod -Uri $rulesUrl -Method Post -Headers @{'X-Auth-Email' = "$email" ; 'X-Auth-Key' = "$token"} -Body $ruleBody
                    $ruleResponse
                    if ($ruleResponse.success -match "False") {
                        $errMsg = $ruleResponse.errors.message
                        Write-Host "Curl request failed with message: $errMsg" ; exit 0
                    }
                    else {
                        #Grab the newly created ruleset ID.
                        $rulesetID = $ruleResponse.result.id
                        Write-Host "New ruleset has been created successfully! The ID is $rulesetID"
                    }
                }
                else {
                    Write-Host "Custom ruleset has been found with ID $rulesetID!"
                }
            }
            $testPhase = curl.exe -s "$url/$zoneID/rulesets" `
                        -H "X-Auth-Email: $email" `
                        -H "X-Auth-Key: $token"
            $testPhase = $testPhase | ConvertFrom-Json
            $customRuleset = $testPhase.result | Where-Object name -like "Static Redirect Ruleset"
            #Store ruleset ID for later.
            $rulesetID = $customRuleset.id
            $testSet = curl.exe -s "$url/$zoneID/rulesets/phases/http_request_dynamic_redirect/entrypoint" `
                        -H "X-Auth-Email: $email" `
                        -H "X-Auth-Key: $token"
            $testSet = $testSet | ConvertFrom-Json

            #Variable to account for www record.
            $modCount = $redirect.count + 1

            #Declare array for counter later.
            $destNum = @()

            #If there was only 1 redirect.
            if ($flag -eq 0) {
                $rOri = $singleRec
                $rDest = $singleDest
                $rC = $testSet.result.rules.Count + 1
                #Rule body.
                $rule = @{
                    "version" = "1"
                    "action" = "redirect"
                    "expression" = "http.host eq `"$rOri`""
                    "description" = "Static redirect rule #$rC"
                    "action_parameters" = @{
                        "from_value" = @{
                            "target_url" = @{
                                "value" = "$rDest"
                            }
                            "status_code" = 301
                        }
                    }   
                    } | ConvertTo-Json -Depth 5
                #HTTP POST to create rule.
                $ruleCreate = Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones/$zoneID/rulesets/$rulesetID/rules" -Method Post -Headers @{'X-Auth-Email' = "$email" ; 'X-Auth-Key' = "$token" ; 'Content-Type' = "application/json"} -Body $rule
                $ruleCreate

                $destNum += $rDest

                $rC++
                #Rule body for www rule.
                $rOri = "www.$domain"
                $rDest = $domain
                $rule = @{
                    "version" = "1"
                    "action" = "redirect"
                    "expression" = "http.host eq $rOri"
                    "description" = "Static redirect rule #$rC"
                    "action_parameters" = @{
                        "from_value" = @{
                            "target_url" = @{
                                "value" = "$rDest"
                            }
                            "status_code" = 301
                        }
                    }       
                    } | ConvertTo-Json -Depth 5
                #HTTP POST to create rule.
                $ruleCreate = Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones/$zoneID/rulesets/$rulesetID/rules" -Method Post -Headers @{'X-Auth-Email' = "$email" ; 'X-Auth-Key' = "$token" ; 'Content-Type' = "application/json"} -Body $rule
                $ruleCreate

                $destNum += $rDest
            }
            elseif ($flag -eq 1) {
                $rC = $testSet.result.rules.Count + 1
                while ($z -le $redirect.count) {
                    $rOri = $redirect.origin[$z]
                    $rDest = $redirect.dest[$z]
                    #Rule body.
                    $rule = @{
                        "version" = "1"
                        "action" = "redirect"
                        "expression" = "http.host eq `"$rOri`""
                        "description" = "Static redirect rule #$rC"
                        "action_parameters" = @{
                            "from_value" = @{
                                "target_url" = @{
                                    "value" = "$rDest"
                                }
                                "status_code" = 301
                            }
                        }   
                        } | ConvertTo-Json -Depth 5
                    #HTTP POST to create rule.
                    $ruleCreate = Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones/$zoneID/rulesets/$rulesetID/rules" -Method Post -Headers @{'X-Auth-Email' = "$email" ; 'X-Auth-Key' = "$token" ; 'Content-Type' = "application/json"} -Body $rule
                    $ruleCreate

                    $destNum += $redirect.dest[$z]
                    $z++
                    $rC++
                }
                #Rule body for www rule.
                $rOri = "www.$domain"
                $rDest = $domain
                $rule = @{
                    "version" = "1"
                    "action" = "redirect"
                    "expression" = "http.host eq $rOri"
                    "description" = "Static redirect rule #$rC"
                    "action_parameters" = @{
                        "from_value" = @{
                            "target_url" = @{
                                "value" = "$rDest"
                            }
                            "status_code" = 301
                        }
                    }       
                    } | ConvertTo-Json -Depth 5
                #HTTP POST to create rule.
                $ruleCreate = Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones/$zoneID/rulesets/$rulesetID/rules" -Method Post -Headers @{'X-Auth-Email' = "$email" ; 'X-Auth-Key' = "$token" ; 'Content-Type' = "application/json"} -Body $rule
                $ruleCreate

                $destNum += $rDest
            }

            #HTTP GET request to see how many http redirect rules exist.
            $testSet = curl.exe -s "$url/$zoneID/rulesets/phases/http_request_dynamic_redirect/entrypoint" `
                        -H "X-Auth-Email: $email" `
                        -H "X-Auth-Key: $token"
            $testSet = $testSet | ConvertFrom-Json

            #If there are any rules.
            if ($testSet.result.rules.Count -gt 0) {
                $b = 0
                $ruleNum = @()
                foreach ($number in $testSet.result.rules) {
                    #Add each rule to an array to check later.
                    $ruleNum += $testSet.result.rules[$b].action_parameters.from_value.target_url.value
                    $b++    
                }
            }

            #If rule count is less than the amount of URL redirects in the URI file , AND is greater than 0.
            if ($testSet.result.rules.count -lt $modCount -and $testSet.result.rules.Count -gt 0) {
                Write-Host "We already found"$testSet.result.rules.Count"rule(s) for $domain. We will delete the existing rules and add what we have back."
                foreach ($staleRule in $testSet.result.rules) {
                    $ruleID = $staleRule.id
                    #HTTP DELETE request to just remove all existing rules so they can be re-added later.
                    $ruleCreate = Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones/$zoneID/rulesets/$rulesetID/rules/$ruleID" -Method Delete -Headers @{'X-Auth-Email' = "$email" ; 'X-Auth-Key' = "$token"}
                    Write-Host "Deleted rule"$ruleCreate.result.id""
                }   
            }
            #If the rule does not contain the destination URL.
            elseif ("$ruleNum" -notmatch "$destNum") {
                Write-Host "The current rules do not match what we have in the URI files. We will remove and re-upload the rules."
                $a = 0
                foreach ($checkRule in $testSet.result.rules) {
                    $redirectTmp = $redirect.dest[$a]
                    #Of all rules in ruleset, check each one individually to see if it matches the destination URL.
                    if ($checkRule.action_parameters.from_value.target_url.value -notmatch "$redirectTmp") {
                        $ruleID = $checkRule.id
                        Write-Host "We found the problem rule. Rule "$ruleID" will be dealt with."
                        #HTTP DELETE request for the violating rule.
                        $ruleCreate = Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones/$zoneID/rulesets/$rulesetID/rules/$ruleID" -Method Delete -Headers @{'X-Auth-Email' = "$email" ; 'X-Auth-Key' = "$token"}
                        Write-Host "Deleted rule"$ruleCreate.result.id""
                    }
                    else {
                        Write-Host "It appears that rule"$checkRule.id" is okay. Continuing."
                    }
                    $a++
                }
            }
            else {
                #If there are no rules at all.
                if ($testSet.result.rules.Count -eq 0) {
                    Write-Host "It looks like there are currently no rules. We will create them now."
                }
                else {
                    Write-Host "It appears that there are already"$redirect.count" rules. Continuing."
                }
            }
            
            #Identical condition, except this is on purpose to trigger when the HTTP DELETE requests are called.
            if ($testSet.result.rules.Count -eq 0) {
                Write-Host "No rules found in this ruleset. We will create a rule for $modCount URI record(s)."
                $r = 0
                while ($r -lt $modCount) {
                    #Rule count for title of rule.
                    $rC = $r + 1
                    if ($flag -eq 1) {
                        $rOri = $redirect.origin[$r]
                        $rDest = $redirect.dest[$r]
                    }
                    elseif ($flag -eq 0) {
                        $rOri = $singleRec
                        $rDest = $singleDest
                    }
                    #Rule body.
                    $rule = @{
                        "version" = "1"
                        "action" = "redirect"
                        "expression" = "http.host eq `"$rOri`""
                        "description" = "Static redirect rule #$rC"
                        "action_parameters" = @{
                            "from_value" = @{
                                "target_url" = @{
                                    "value" = "$rDest"
                                }
                                "status_code" = 301
                            }
                        }
                    } | ConvertTo-Json -Depth 5
                    #HTTP POST to create rule.
                    $ruleCreate = Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones/$zoneID/rulesets/$rulesetID/rules" -Method Post -Headers @{'X-Auth-Email' = "$email" ; 'X-Auth-Key' = "$token" ; 'Content-Type' = "application/json"} -Body $rule
                    $ruleCreate
                    if ($ruleCreate.success -match "False") {
                        Write-Host "Creating rules failed with the error :"$ruleCreate.errors.message"" ; exit 0
                    }
                    else {
                        Write-Host "Rule #$rC created successfully! Rule ID:"$ruleCreate.result.id""
                    }
                    $r++
                }
            }
            elseif ($testSet.result.rules.count -lt $modCount) {
                Write-Host "Not enough rules found in this ruleset. We will create a rule for"($modCount - $testSet.result.rules.count)" URI record(s)."
                $r = $testSet.result.rules.count
                while ($r -lt $redirect.Count) {
                    #Rule count for title of rule.
                    $rC = $r + 1
                    if ($flag -eq 1) {
                        $rOri = $redirect.origin[$r]
                        $rDest = $redirect.dest[$r]
                    }
                    elseif ($flag -eq 0) {
                        $rOri = $singleRec
                        $rDest = $singleDest
                    }
                    #Rule body.
                    $rule = @{
                        "version" = "1"
                        "action" = "redirect"
                        "expression" = "http.host eq `"$rOri`""
                        "description" = "Static redirect rule #$rC"
                        "action_parameters" = @{
                            "from_value" = @{
                                "target_url" = @{
                                    "value" = "$rDest"
                                }
                                "status_code" = 301
                            }
                        }
                    } | ConvertTo-Json -Depth 5
                    #HTTP POST to create rule.
                    $ruleCreate = Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones/$zoneID/rulesets/$rulesetID/rules" -Method Post -Headers @{'X-Auth-Email' = "$email" ; 'X-Auth-Key' = "$token" ; 'Content-Type' = "application/json"} -Body $rule
                    $ruleCreate
                    if ($ruleCreate.success -match "False") {
                        Write-Host "Creating rules failed with the error :"$ruleCreate.errors.message"" ; exit 0
                    }
                    else {
                        Write-Host "Rule #$rC created successfully! Rule ID:"$ruleCreate.result.id""
                    }
                    $r++
                }
                #Rule body for www rule.
                $rC++
                $hostVal = "www.$rOri"
                $rule = @{
                    "version" = "1"
                    "action" = "redirect"
                    "expression" = "http.host eq $hostVal"
                    "description" = "Static redirect rule #$rC"
                    "action_parameters" = @{
                        "from_value" = @{
                            "target_url" = @{
                                "value" = "$rDest"
                            }
                            "status_code" = 301
                        }
                    }   
                    } | ConvertTo-Json -Depth 5
                #HTTP POST to create rule.
                $ruleCreate = Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones/$zoneID/rulesets/$rulesetID/rules" -Method Post -Headers @{'X-Auth-Email' = "$email" ; 'X-Auth-Key' = "$token" ; 'Content-Type' = "application/json"} -Body $rule
                $ruleCreate

                $destNum += $rDest
            }
        }
    }
    try{
        Write-Host "Sending a curl post request to import DNS records for $domain..."
         #CURL request for all DNS records for cloudflare domain.
        $response = curl.exe -s -X POST "$url/$zoneID/dns_records/import" `
                -H "X-Auth-Email: $email" `
                -H "X-Auth-Key: $token" `
                -F "file=@$recordFile"
        Write-Host "Sleeping for 5s to prevent rate limiting..." ; Start-Sleep 5
        Write-Host $response
    } 
    catch { Write-Host "Curl request for importing DNS records failed."}

    $x = 0
    Write-Host "Sending a curl request for all dnsimple NS records..."
    while ($x -lt 4) {
        #There will usually always be 4 NS records for DNSimple. Check for all DNS records containing dnsimple.com.
        $uri = "$url/$zoneID/dns_records?content.contains=dnsimple.com"

        try {
            #CURL request for said NS records.
            $resp = curl.exe -s $uri `
                    -H "X-Auth-Email: $email" `
                    -H "X-Auth-Key: $token" `
                    -H "Content-Type: application/json"
        } 
        catch { Write-Host "Curl request for dnsimple NS records failed."}

        $nsRec = ConvertFrom-Json $resp

        #If no records are found.
        if ($nsRec.result_info.count -eq 0) {
            Write-Host "$domain does not contain any DNSimple NS records. Nothing to be done here!"
            break
        }
        else {
            #Set the 0th (first) record for deletion.
            $nsNuke = $nsRec.result[0].id

            try {
                #CURL request to delete said record.
                curl.exe -s "$url/$zoneID/dns_records/$nsNuke" `
                        -X DELETE `
                        -H "X-Auth-Email: $email" `
                        -H "X-Auth-Key: $token"
            } 
            catch { Write-Host "Curl request to delete NS record failed."}
        }
        $x++
        Write-Host "Sleeping for 5s to prevent rate limiting..." ; Start-Sleep 5
    }
    Write-Host "$x NS records deleted."
    #If the current domain is within the redo file, and current line + 1 will not exceed the total line count.
    if ((Get-content $path) -contains $domain -and ($L + 1) -le $ct.Lines ){
        #Remove domain name from redo file.
        (Get-Content $path) -replace $domain, "" | Set-Content -Path $path
        $L++
        #Do it all over again.
        import-again
    }
    #If the domain was not found after 3 tries.
    elseif ($j -eq -1 -and $f -eq 3) {
        Write-Host "$domain does not exist in the Cloudflare zone file yet. We tried to locate it. $domain will be output to 'RedoNameServ.txt' if it is not already there, so you can revisit later and re-run the importZones function."
        #Check again if we are already running from the redo file.
        if ((Get-content $path) -contains $domain -and ($L + 1) -le $ct.Lines ){
            $L++
            import-again
        }
        #If the domain is not in the redo file, put it there.
        elseif ((Get-Content $path) -notcontains $domain){
            $domain | Out-File -Append -FilePath "C:\Users\$env:username\Downloads\RedoNameServ.txt"

            if (Test-Path "C:\Users\$env:username\Downloads\RedoNameServ.txt") {

                Write-Host "Now that's done, Returning to addDomain!"
            }
        }
    else {
        Write-Host "Re-Run of importZones has completed." ; exit 0
    }
}

Write-Host "
_________ .__                   .___ _____.__                       ________                        .__                          ____ 
\_   ___ \|  |   ____  __ __  __| _// ____\  | _____ _______   ____ \______ \   ____   _____ _____  |__| ____      ______  _____/_   |
/    \  \/|  |  /  _ \|  |  \/ __ |\   __\|  | \__  \\_  __ \_/ __ \ |    |  \ /  _ \ /     \\__  \ |  |/    \     \____ \/  ___/|   |
\     \___|  |_(  <_> )  |  / /_/ | |  |  |  |__/ __ \|  | \/\  ___/ |    `   (  <_> )  Y Y  \/ __ \|  |   |  \    |  |_> >___ \ |   |
 \______  /____/\____/|____/\____ | |__|  |____(____  /__|    \___  >_______  /\____/|__|_|  (____  /__|___|  / /\ |   __/____  >|___|
        \/                       \/                 \/            \/        \/             \/     \/        \/  \/ |__|       \/      



"
#Give the user the illusion of free will.
$ans = Read-Host "What function would you like to run?

Download DNSimple Zone File (1)
Add a domain to Cloudflare (2)
Re-Run Cloudflare NS Records Update (3)
"
if ($ans -eq 1) {
    Write-Host "Running DNS Zone function!" ; get-dnszone
}
elseif ($ans -eq 2) {
    Write-Host "Running Add Domain function!" ; initialize-creds ; addDomain
}
elseif ($ans -eq 3) {
    Write-Host "Running Zone Import function!" ; initialize-creds ; import-again
}
else {
    Write-Host "You did not input a valid answer. Please enter 1, 2, or 3." ; exit 0
}



