$version = "0.2.0" 
$moduleBaseUrl = [System.Environment]::GetEnvironmentVariable("Ncentralps_BASE_URL", "User")

function get-ncentralmoduleversion {
    write-host "N-Centralpowershell module version: "$version
  }

Function set-NCentralBasurl{
    #set-NCentralBasurl -url "rmm.example.com"
    param(
        [string]$url
    )
    $ncentralbaseurl = "https://"+$url
    [System.Environment]::SetEnvironmentVariable("Ncentralps_BASE_URL", "$ncentralbaseurl", "User")
    $script:moduleBaseUrl = $ncentralbaseurl
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
        $rtoken = $AuthResponse.tokens.refresh.token
        $AuthHeaders = @{ "Authorization" = "Bearer $AccessToken" }
        $urivalidate = $moduleBaseUrl + "/api/auth/validate"
        $AuthValidate = Invoke-RestMethod -Uri $urivalidate -Headers $AuthHeaders -Method Get -ContentType "application/json"
        #return $AuthValidate.message
        $results = [PSCustomObject]@{
            status = $AuthValidate.message
            header = $AuthHeaders
            token  = $AccessToken
            Refreshtoken = $rtoken
        }
        return $results
    }
    catch {
        Write-Host $_
    }
}

function get-refreshtoken {
    # $auth = get-refreshtoken -authtoken $auth.token -refreshtoken $auth.Refreshtoken
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$authtoken,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [string]$refreshtoken
    )
    
    $urivalidate = $moduleBaseUrl + "/api/auth/validate"
    $authheaders = @{ "Authorization" = "Bearer $authtoken" }
    $AuthValidate = Invoke-RestMethod -Uri $urivalidate -Headers $authheaders -Method Get -ContentType "application/json"
    if ($AuthValidate.message -ne "The token is valid.") {
        try{
            $urirefresh = $moduleBaseUrl + "/api/auth/refresh"
            $authheaders = @{ "Authorization" = "Bearer $authtoken" }
            $refreshtoken = Invoke-RestMethod -Uri $urirefresh -Headers $authheaders -body $refreshtoken -Method POST -ContentType "text/plain"
            $AccessToken = $refreshtoken.tokens.access.token
            $rtoken = $refreshtoken.tokens.refresh.token
            $AuthHeaders = @{ "Authorization" = "Bearer $AccessToken" }
            $AuthValidate = Invoke-RestMethod -Uri $urivalidate -Headers $AuthHeaders -Method Get -ContentType "application/json"
            write-host $AuthValidate.message
            $refreshresults = [PSCustomObject]@{
                status = $AuthValidate.message
                header = $AuthHeaders
                token  = $AccessToken
                Refreshtoken = $rtoken
            }
            return $refreshresults
        }
        catch {
            Throw "Refresh Token expired, start a new session"
        }
    }
}

function get-NCentralconnectionstate{
    # get-N-Centralconnectionstate -authtoken $auth.token
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$authtoken
    )
    $urivalidate = $moduleBaseUrl + "/api/auth/validate"
    $authheaders = @{ "Authorization" = "Bearer $authtoken" }
    $AuthValidate = Invoke-RestMethod -Uri $urivalidate -Headers $authheaders -Method Get -ContentType "application/json"
    If ($AuthValidate.message -eq "The Token is valid."){
        Write-host "Connection is active, you have a connection to $moduleBaseUrl"
    }
    else{
        Throw "connection is not active"
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
    # $CCP = get-ncentralcustomcustomerproperties -authtoken $auth.token -Customerid 122 -propertyid 123456789
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$authtoken,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [string]$Customerid,
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $true)]
        [string]$PropertyID
    )    
    
    $uriCCP =  $moduleBaseUrl + "/api/org-units/$Customerid/custom-properties"
    $authheaders = @{"Authorization" = "Bearer $authtoken"}
    $CCPrequest = (Invoke-RestMethod -Uri $uriCCP -Headers $authheaders -Method GET)
    
    If ($null -ne $PropertyID -and $PropertyID -ne ""){
        write-host $PropertyID
        $CCPresponse = $CCPrequest.properties | where-object { $_.propertyId -eq $PropertyID }
    }
    else{
        $CCPresponse = $CCPrequest.properties
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

function get-ncentralcustomdeviceproperties {
    # $CDP = get-ncentralcustomdeviceproperties -authtoken $auth.token -deviceid 123456789 -propertyid 123456789
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$authtoken,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [string]$deviceid,
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $true)]
        [string]$PropertyID
    )    
    
    $uriCDP =  $moduleBaseUrl + "/api/devices/$deviceid/custom-properties"
    write-host $uriCDP
    $authheaders = @{"Authorization" = "Bearer $authtoken"}
    $CDPrequest = (Invoke-RestMethod -Uri $uriCDP -Headers $authheaders -Method GET)
    
    If ($null -ne $PropertyID -and $PropertyID -ne ""){
        $CDPresponse = $CDPrequest.data | where-object { $_.propertyId -eq $PropertyID }
    }
    else{
        $CDPresponse = $CDPrequest.data
    }

    return $CDPresponse
}


##Export Functions
Export-ModuleMember -Function "set-NCentralBasurl",
"get-NCentralBasurl",
"remove-NCentralBasurl",
"get-ncentralmoduleversion",
"Get-NcentralBearerAuth",
"get-refreshtoken",
"get-NCentralconnectionstate",
"get-NCentralCustomers",
"get-ncentralcustomcustomerproperties",
"get-ncentraldevices",
"get-ncentralcustomdeviceproperties"

