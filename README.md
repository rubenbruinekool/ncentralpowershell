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
### Version 0.2.0
* Use now Environment variable for the baseurl
* Added new function get-ncentralcustomcustomerproperties
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

### Refresh Token !!WILL NOT WORK!!
create a refreshtoken, but this will not work at this moment.
```
$auth = get-refreshtoken -authtoken $auth.token -refreshtoken $auth.Refreshtoken
```

### ConnectionState
Check if the connection is active to the N-Central server
```
get-N-Centralconnectionstate -authtoken $auth.token
```
### Custommers
```
get-NCentralCustomers -authtoken $auth.token
```

### Custom Customer properties
```
get-ncentralcustomcustomerproperties -authtoken $auth.token -Customerid 122 -propertyid 123456789
```


###Devicefilters
This will get all the filters they are in the dropdownmenu of the API user.
```
$allfilters = get-ncentraldevicefilters -authtoken $auth.token
```

###devices
Get all the devices for the API User
```
$devices = get-ncentraldevices -authtoken $auth.token
```

You can also get the devices with a filter, then you must insert the filterId.
```
$devices = get-ncentraldevices -authtoken $auth.token -filterid 1
```

###Get Custom device properties
To get the custom device properties of a device you must insert the deviceId,
```
$CDP = get-ncentralcustomdeviceproperties -authtoken $auth.token -deviceid 123456789
```

To filter you Custom device properties, you can insert an PropertyId
```
$CDP = get-ncentralcustomdeviceproperties -authtoken $auth.token -deviceid 1738191393 -propertyid 1717105908
```


### Get the current module version
You will get the version of my module with the following command:<br>
```
get-ncentralmoduleversion
```






