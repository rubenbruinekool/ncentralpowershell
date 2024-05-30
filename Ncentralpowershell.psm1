#$JWTtoken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJTb2xhcndpbmRzIE1TUCBOLWNlbnRyYWwiLCJ1c2VyaWQiOjM1ODIzODMzNSwiaWF0IjoxNzE3MDUzOTE1fQ.VpXi0teFRDWHtNPBXy5jkhM7XhSm0qLeoDIHBha2FvA"

$version = 0.1.0

function get-ncentralmoduleversion {
    write-host $version
  }

Function set-NCentralBasurl{
    param(
        [string]$url
    )
    $script:baseUrl = "https://"+$url
}

function get-NCentralBasurl{
    write-host $script:baseurl
}

function remove-NCentralBasurl {
    $script:baseUrl = ""
}

function Get-NcentralBearerAuth {
    # $auth = Get-NcentralBearerAuth -JWT $JWTTOKEN
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$JWTtoken
    )
    try {
        $uriauth = $script:baseurl + "/api/auth/authenticate"
        $AuthResponse = Invoke-RestMethod -Uri $uriauth -Headers @{ "Authorization" = "Bearer $JWTToken" } -Method Post -ContentType "application/json"
        $AccessToken = $AuthResponse.tokens.access.token
        $rtoken = $AuthResponse.tokens.refresh.token
        $AuthHeaders = @{ "Authorization" = "Bearer $AccessToken" }
        $urivalidate = $script:baseurl + "/api/auth/validate"
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
    
    $urivalidate = $script:baseurl + "/api/auth/validate"
    $authheaders = @{ "Authorization" = "Bearer $authtoken" }
    $AuthValidate = Invoke-RestMethod -Uri $urivalidate -Headers $authheaders -Method Get -ContentType "application/json"
    if ($AuthValidate.message -ne "The token is valid.") {
        try{
            $urirefresh = $script:baseurl + "/api/auth/refresh"
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
    $urivalidate = $script:baseurl + "/api/auth/validate"
    $authheaders = @{ "Authorization" = "Bearer $authtoken" }
    $AuthValidate = Invoke-RestMethod -Uri $urivalidate -Headers $authheaders -Method Get -ContentType "application/json"
    If ($AuthValidate.message -eq "The Token is valid."){
        Write-host "Connection is active, you have a connection to $script:baseurl"
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

    $uricustomers = $script:baseurl + "/api/customers"
    $authheaders = @{ "Authorization" = "Bearer $authtoken" }

    while ($null -ne $uricustomers -and $uricustomers -ne ""){
        write-host $uricustomers
        try{
            $Customerrequest = Invoke-RestMethod -Uri $uricustomers -Headers $authheaders -Method Get -ContentType "application/json"
            $allCustomers += $Customerrequest.data

            if ($Customerrequest._links -and $Customerrequest._links.nextPage) {
                $nextpage = $Customerrequest._links.nextPage
                $uricustomers = $script:baseurl + $nextpage
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


function get-ncentraldevicefilters {
    #$allfilters = get-ncentraldevicefilters -authtoken $auth.token
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$authtoken
    )
    $uridevicefilters= $script:baseurl + "/api/device-filters"
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
        $uridevices = $script:baseurl + "/api/devices"
    }
    else {
        $uridevices =  $script:baseurl + "/api/devices?filterId=$filterid&sortOrder=ASC"
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
                $uridevices = $script:baseurl + $nextpage + "&filterId=$filterid&sortOrder=ASC"
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
    
    $uriCDP =  $script:baseurl + "/api/devices/$deviceid/custom-properties"
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
"get-ncentraldevices",
"get-ncentralcustomdeviceproperties"

