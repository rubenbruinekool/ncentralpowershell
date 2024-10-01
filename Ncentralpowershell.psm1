####################################################################################
# _   _        _____            _             _                                   
# | \ | |      /  __ \          | |           | |                                  
# |  \| |______| /  \/ ___ _ __ | |_ _ __ __ _| |                                  
# | . ` |______| |    / _ \ '_ \| __| '__/ _` | |                                  
# | |\  |      | \__/\  __/ | | | |_| | | (_| | |                                  
# \_| \_/       \____/\___|_| |_|\__|_|  \__,_|_|                                  
# ______                          _          _ _  ___  ___          _       _      
# | ___ \                        | |        | | | |  \/  |         | |     | |     
# | |_/ /____      _____ _ __ ___| |__   ___| | | | .  . | ___   __| |_   _| | ___ 
# |  __/ _ \ \ /\ / / _ \ '__/ __| '_ \ / _ \ | | | |\/| |/ _ \ / _` | | | | |/ _ \
# | | | (_) \ V  V /  __/ |  \__ \ | | |  __/ | | | |  | | (_) | (_| | |_| | |  __/
# \_|  \___/ \_/\_/ \___|_|  |___/_| |_|\___|_|_| \_|  |_/\___/ \__,_|\__,_|_|\___|
####################################################################################
# Created by Ruben Bruinekool, version 0.4.0
####################################################################################

$version = "0.4.0" 
$moduleBaseUrl = [System.Environment]::GetEnvironmentVariable("Ncentralps_BASE_URL", "User")
write-host "De volgende url is ingesteld als standaard vanuit de module: $modulebaseurl"                                                                             

function get-ncentralmoduleversion {
    write-host "N-Centralpowershell module version: "$version
  }

Function set-NCentralBasurl{
    #set-NCentralBasurl -url "rmm.example.com"
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$url
    )
    $ncentralbaseurl = "https://"+$url
    [System.Environment]::SetEnvironmentVariable("Ncentralps_BASE_URL", "$ncentralbaseurl", "User")
    $moduleBaseUrl = $ncentralbaseurl
    write-host "NCentralbaseurl ingesteld op $modulebaseurl"
}

function get-NCentralBasurl{
    $baseUrl = [System.Environment]::GetEnvironmentVariable("Ncentralps_BASE_URL", "User")
    if ($null -eq $baseUrl) {
        Write-Error "BASE_URL is not set."
    } else {
        Write-Output $baseUrl
    }
}

function remove-NCentralBasurl {
    [System.Environment]::SetEnvironmentVariable("Ncentralps_BASE_URL", $null, "User")
}

function Get-NcentralBearerAuth {
    # $auth = Get-NcentralBearerAuth -JWT $JWTTOKEN
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$JWTtoken
    )
    try {
       
        $uriauth = $moduleBaseUrl + "/api/auth/authenticate"
        $AuthResponse = Invoke-RestMethod -Uri $uriauth -Headers @{ "Authorization" = "Bearer $JWTToken" } -Method Post -ContentType "application/json"
        $AccessToken = $AuthResponse.tokens.access.token
        $expiresecondsaccess = $AuthResponse.tokens.access.expirySeconds
        $rtoken = $AuthResponse.tokens.refresh.token
        $expiresecondsrefresh = $AuthResponse.tokens.refresh.expirySeconds
        $AuthHeaders = @{ "Authorization" = "Bearer $AccessToken" }
        $urivalidate = $moduleBaseUrl + "/api/auth/validate"
        $AuthValidate = Invoke-RestMethod -Uri $urivalidate -Headers $AuthHeaders -Method Get -ContentType "application/json"
        #return $AuthValidate.message
        $results = [PSCustomObject]@{
            status = $AuthValidate.message
            header = $AuthHeaders
            token  = $AccessToken
            expireaccesstoken = $expiresecondsaccess
            Refreshtoken = $rtoken
            expirerefreshtoken = $expiresecondsrefresh
        }
        return $results
    }
    catch {
        Write-Host $_
    }
}

function update-NcentralBearerAuth {
    #$auth = get-refreshtoken -auth $auth.token -refreshtoken $auth.refreshtoken
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$authtoken,
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$refreshtoken
    )

    $validateURL = $moduleBaseUrl + "/api/auth/validate"
    $authheaders = @{
        "accept"        = "application/json"
        "Authorization" = "Bearer $($authtoken)"
    }
    $ValidateResponse = Invoke-RestMethod -Uri $validateURL -Method Get -Headers $authheaders -ErrorAction SilentlyContinue
    if ($ValidateResponse.message -eq "The token is valid.") {
        try {
            $RefreshURL = $moduleBaseUrl + "/api/auth/refresh"
            $RefreshHeaders = @{
                "accept"        = "*/*"
                "Authorization" = "Bearer $($authtoken)"
                "Content-Type"  = "text/plain"
            }
            $RefreshResponse = Invoke-RestMethod -Uri $RefreshURL -Method Post -Headers $RefreshHeaders -Body $refreshtoken
            
            $AccessToken = $RefreshResponse.tokens.access.token
            $expiresecondsaccess = $RefreshResponse.tokens.access.expirySeconds
            $rtoken = $RefreshResponse.tokens.refresh.token
            $expiresecondsrefresh = $RefreshResponse.tokens.refresh.expirySeconds
        
            $results = [PSCustomObject]@{
                token  = $AccessToken
                expireaccesstoken = $expiresecondsaccess
                Refreshtoken = $rtoken
                expirerefreshtoken = $expiresecondsrefresh
            }
            return $results
        }
        catch {
            Throw "Refresh Token expired, start a new session"
        }
    }
    else{
        write-host $ValidateResponse.message
    }
}

function get-NCentralconnectionstate{
    # get-N-Centralconnectionstate -authtoken $auth.token
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$authtoken
    )

    try{
        $urivalidate = $moduleBaseUrl + "/api/auth/validate"
        $authheaders = @{ "Authorization" = "Bearer $authtoken" }
        $AuthValidate = Invoke-RestMethod -Uri $urivalidate -Headers $authheaders -Method Get -ContentType "application/json" -ErrorAction Stop -Verbose:$false
        Write-Verbose "Token is still valid, not refreshing"
        Write-host "Connection is active, you have a connection to $moduleBaseUrl"
    }
    catch{
        Write-Verbose "Token is no longer valid. Trying to refresh"
        write-host "Token is not valid, it must be refreshed"
    }
}

function get-NCentralCustomers{
    # get-NCentralCustomers -authtoken $auth.token
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$authtoken
    )

    $allCustomers = @()

    $uricustomers = $moduleBaseUrl + "/api/customers"
    $authheaders = @{ "Authorization" = "Bearer $authtoken" }

    while ($null -ne $uricustomers -and $uricustomers -ne ""){
        write-host $uricustomers
        try{
            $Customerrequest = Invoke-RestMethod -Uri $uricustomers -Headers $authheaders -Method Get -ContentType "application/json"
            $allCustomers += $Customerrequest.data

            if ($Customerrequest._links -and $Customerrequest._links.nextPage) {
                $nextpage = $Customerrequest._links.nextPage
                $uricustomers = $moduleBaseUrl + $nextpage
                } 
                else{
                    $uricustomers = $null
                }
            }
        catch{
            write-error "Ër is een fout : $_"
            break
        }
    }

    return $allCustomers
}

function get-ncentralcustomcustomerproperties {
    # $CCP = get-ncentralcustomcustomerproperties -authtoken $auth.token -Customerid 122 -propertyid 1634038205
    # $CCP = get-ncentralcustomcustomerproperties -authtoken $auth.token -Customerid 122
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$authtoken,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [string]$Customerid,
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $true)]
        [string]$PropertyID
    )    
    write-host $moduleBaseUrl
    If ($null -ne $PropertyID -and $PropertyID -ne ""){
        $uriCCP =  $moduleBaseUrl + "/api/org-units/$Customerid/custom-properties/$propertyID"
    }
    else{
        $uriCCP =  $moduleBaseUrl + "/api/org-units/$Customerid/custom-properties"
    }
    write-host $uriCCP

    $authheaders = @{"Authorization" = "Bearer $authtoken"}
    $CCPrequest = (Invoke-RestMethod -Uri $uriCCP -Headers $authheaders -Method GET)

    If ($null -ne $PropertyID -and $PropertyID -ne ""){
    $CCPresponse = $CCPrequest
    }
    else{
        $CCPresponse = $CCPrequest.data
    }
    return $CCPresponse
}

function get-ncentraldevicefilters {
    #$allfilters = get-ncentraldevicefilters -authtoken $auth.token
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$authtoken
    )
    $uridevicefilters= $moduleBaseUrl + "/api/device-filters"
    $authheaders = @{ "Authorization" = "Bearer $authtoken" }
    $Devicefilters = Invoke-RestMethod -Uri $uridevicefilters -Headers $authheaders -Method GET -ContentType "application/json"
    $alldropdownfilters = $Devicefilters.data
    
    return $alldropdownfilters
}

function get-ncentraldevices {
    # $devices = get-ncentraldevices -authtoken $auth.token -filterid 1 
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$authtoken,
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $true)]
        [string]$filterid
    )

    $alldevices = @()
   
    if($null -eq $filterid){
        $uridevices = $moduleBaseUrl + "/api/devices"
    }
    else {
        $uridevices =  $moduleBaseUrl + "/api/devices?filterId=$filterid&sortOrder=ASC"
    }

    $alldevices = @()

    $authheaders = @{ "Authorization" = "Bearer $authtoken" }
    while ($null -ne $uridevices -and $uridevices -ne ""){
        write-host $uridevices
        try{
            $getdevices = Invoke-RestMethod -Uri $uridevices -Headers $authheaders -Method GET
            $alldevices += $getdevices.data

            if ($getdevices._links -and $getdevices._links.nextPage) {
                $nextpage = $getdevices._links.nextPage
                $uridevices = $moduleBaseUrl + $nextpage + "&filterId=$filterid&sortOrder=ASC"
                } 
                else{
                    $uridevices = $null
                }
            }
        catch{
            write-error "Ër is een fout : $_"
            break
        }
    }
    return $alldevices
}

function get-ncentraldeviceassetinfo {
    # $deviceasset = get-ncentraldeviceassetinfo -authtoken $auth.token -deviceid 1496519025 
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$authtoken,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [string]$deviceid
    )

    $urideviceasset =  $moduleBaseUrl + "/api/devices/$deviceid/assets"
    $authheaders = @{ "Authorization" = "Bearer $authtoken" }
    try{
        $getdeviceassetinfo = Invoke-RestMethod -Uri $urideviceasset -Headers $authheaders -Method GET            
        }
    catch{
        write-error "Ër is een fout : $_"
        break
    }
    return $getdeviceassetinfo.data
}

function get-ncentraldevicemonitoringstatus {
    # $devicemonitoringstatus = get-ncentraldevicemonitoringstatus -authtoken $auth.token -deviceid 1496519025 
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$authtoken,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [string]$deviceid
    )
    $uridevicemonitoringstatus =  $moduleBaseUrl + "/api/devices/$deviceid/service-monitor-status"
    write-host $uridevicemonitoringstatus

    $authheaders = @{ "Authorization" = "Bearer $authtoken" }
    try{
        $getdevicemonitoringstatus = Invoke-RestMethod -Uri $uridevicemonitoringstatus -Headers $authheaders -Method GET            
        }
    catch{
        write-error "Ër is een fout : $_"
        break
    }
    return $getdevicemonitoringstatus.data
}


function get-ncentralcustomdeviceproperties {
    # $CDP = get-ncentralcustomdeviceproperties -authtoken $auth.token -deviceid 123456789 -propertyid 123456789
    # $CDP = get-ncentralcustomdeviceproperties -authtoken $auth.token -deviceid 123456789
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$authtoken,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [string]$deviceid,
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $true)]
        [string]$PropertyID
    )    

    If ($null -ne $PropertyID -and $PropertyID -ne ""){
        $uriCDP =  $moduleBaseUrl + "/api/devices/$deviceid/custom-properties/$propertyID"
    }
    else{
        $uriCDP =  $moduleBaseUrl + "/api/devices/$deviceid/custom-properties"
    }
    write-host $uriCDP

    $auth  = @{"Authorization" = "Bearer $authtoken"}
    $CDPrequest = (Invoke-RestMethod -Uri $uriCDP -Headers $authheaders -Method GET)
    
    $CDPresponse = $CDPrequest

    return $CDPresponse
}
function set-ncentralcustomdeviceproperty {
    # $setCDP = set-ncentralcustomdeviceproperty -authtoken $auth.token -deviceid 123456789 -propertyid 123456789 -cdpvalue test
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$authtoken,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [string]$deviceid,
        [Parameter(Mandatory = $true, Position = 2, ValueFromPipeline = $true)]
        [string]$PropertyID,
        [Parameter(Mandatory = $true, Position = 3, ValueFromPipeline = $true)]
        [string]$cdpvalue
    )    
    
    $uriCDP =  $moduleBaseUrl + "/api/devices/$deviceid/custom-properties/$PropertyID"
    $Body = @{
        "value" = $cdpvalue
    } | ConvertTo-Json
    $authheaders = @{
        "Authorization" = "Bearer $authtoken"
        "content-type" = "application/json"
    }
    $setCDPrequest = (Invoke-RestMethod -Uri $uriCDP -Headers $authheaders -Body $Body -Method PUT)
    write-host $setCDPrequest
    $setCDPresponse = $setCDPrequest

    return $setCDPresponse
}


function get-Ncentralactiveissues {
    #$activeissues = get-Ncentralactiveissues -authtoken $auth.token -orgid "50"
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$authtoken,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [string]$Orgid
    )    

    $uriactiveissue =  $moduleBaseUrl + "/api/org-units/$orgid/active-issues"
    write-host $uriactiveissue
    $authheaders = @{ 
        "Authorization" = "Bearer $authtoken"
        "content-type" = "application/json"
    }
    $getactiveissues = (Invoke-RestMethod -Uri $uriactiveissue -Headers $authheaders -Method Get)
    write-host $getactiveissues

    return $getactiveissues
}


##Export Functions
Export-ModuleMember -Function "set-NCentralBasurl",
"get-NCentralBasurl",
"remove-NCentralBasurl",
"get-ncentralmoduleversion",
"Get-NcentralBearerAuth",
"update-NcentralBearerAuth",
"get-NCentralconnectionstate",
"get-NCentralCustomers",
"get-ncentralcustomcustomerproperties",
"get-ncentraldevicefilters",
"get-ncentraldevices",
"get-ncentralcustomdeviceproperties",
"set-ncentralcustomdeviceproperty",
"get-ncentraldeviceassetinfo",
"get-ncentraldevicemonitoringstatus",
"get-Ncentralactiveissues"

