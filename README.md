# ncentralpowershell
# ReadMe

## Content
 * [Basics](#basics)
 * [Disclaimer and Warning](#disclaimer-and-warning)
 * [Release Notes](#release-notes)
 * [Ussage](*Ussage)

## Basics
Install the powershell module to download the ncentralpowershell folder and copy this files to your powershell module folder
This module is based on version 2024.2.0.20 of N-Central

# Import module
```
import-module -name "ncentralpowershell"
```

## Disclaimer and Warning
**Be careful!** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


## Release notes
### Version 0.4.0
* Created a working refresh-token commando
* Refresh token changed to update-NcentralBearerAuth
* rewrite the get-NCentralconnectionstate
### Version 0.2.0
* added new function get-ncentraldeviceassetinfo
* added new function get-ncentraldevicemonitoringstatus
### Version 0.2.0
* Use now Environment variable for the baseurl
* Added new function get-ncentralcustomcustomerproperties
* Bugfixes
### Version 0.1.1
* added a query to get all customers
### Version 0.1.0
* Created module with first commando's

## Ussage
### BaseURL
You can set the baseurl by use the following command:<br>
```
set-NCentralBasurl -url example.com
```

You can view the baseurl with the following command:<br>
```
get-NCentralBasurl
```
You can remove the baseurl with the following command:<br>
```
remove-NCentralBasurl
```

### Authentication Token
You can create a bearer token with the following command:<br>
```
$auth = Get-NcentralBearerAuth -JWT JWTTOKEN
```

### Refresh Token
create a new token with the refresh token.
```
$rauth = update-NcentralBearerAuth -authtoken $auth.token -refreshtoken $auth.Refreshtoken
$auth = $rauth
```


### ConnectionState
Check if the connection is active to the N-Central server
```
get-N-Centralconnectionstate -authtoken $auth.token
```
### Customers
```
get-NCentralCustomers -authtoken $auth.token
```

### Custom Customer properties
To get the custom Customer properties of a Customer you must insert the CustomerID,
```
$CCP = get-ncentralcustomcustomerproperties -authtoken $auth.token -Customerid 123
```

To filter you Custom Customer properties, you can insert an PropertyId
```
$CCP = get-ncentralcustomcustomerproperties -authtoken $auth.token -Customerid 123 -propertyid 123456789
```

### Devicefilters
This will get all the filters they are in the dropdownmenu of the API user.
```
$allfilters = get-ncentraldevicefilters -authtoken $auth.token
```

### Devices
Get all the devices for the API User
```
$devices = get-ncentraldevices -authtoken $auth.token
```

You can also get the devices with a filter, then you must insert the filterId.
```
$devices = get-ncentraldevices -authtoken $auth.token -filterid 1
```

### Device asset info
Get the device asset info.
```
$deviceasset = get-ncentraldeviceassetinfo -authtoken $auth.token -deviceid 123456789 
```
### Monitoring status
Get the monitoring status of a device
```
$devicemonitoringstatus = get-ncentraldevicemonitoringstatus -authtoken $auth.token -deviceid 123456789 
```


### Custom device properties
To get the custom device properties of a device you must insert the deviceId,
```
$CDP = get-ncentralcustomdeviceproperties -authtoken $auth.token -deviceid 123456789
```

To filter you Custom device properties, you can insert an PropertyId
```
$CDP = get-ncentralcustomdeviceproperties -authtoken $auth.token -deviceid 123456789 -propertyid 123456789
```


### Get the current module version
You will get the version of my module with the following command:<br>
```
get-ncentralmoduleversion
```






