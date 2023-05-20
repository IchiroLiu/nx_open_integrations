// Copyright 2018-present Network Optix, Inc. Licensed under MPL 2.0: www.mozilla.org/MPL/2.0/

# Build a mapping of resources and accounts in the system.

Nx Witness allows third-party developers to retrieve the resource(Devices, Webpages, Layouts, and server health graphs) from their system database using the mediaserver API.

We provide examples and explanations for the new API available in Nx Witness 5.0 (and newer). Refer to [Nx Server HTTP REST API](https://support.networkoptix.com/hc/en-us/articles/219573367-Nx-Server-HTTP-REST-API) for more information on our APIs and on accessing our API documentation.

## Using the Sample Scripts

The sample scripts provided in the repository are a basic demonstration of what scripts that use the system API calls could look like. Ex: you can see that we retrieve the resource infomration from the system databse in this case. The scripts also contain the code of the implementation of authentication. (refer to the [Authentication](#authentication) section below).

To test the examples, input your information where applicable and run it.

#### Authentication

Nx Witness 5.0 uses HTTP bearer/session token authentication. We perform the API requests below as local users. Refer to [Nx Meta Authentication](https://support.networkoptix.com/hc/en-us/articles/4410505014423-Nx-Meta-Authentication) for more info.

### How to retrieve the resources and users from a System
The API requests used to retrieve the resources from the system are the following:
*  Devices: `GET /rest/v2/devices`
*  Layouts: `GET /rest/v2/layouts`
*  Wepages: `GET /rest/v2/webPages`
*  Servers: `GET /rest/v2/servers`
*  Users:   `GET /rest/v2/users`

The requests will return you a JSON object that containing the detailed information of each resource.  YOu can retrieve the desired value by parsing the JSON.

### How to create the mapping of a resource and associated accounts
In the response of the API, `GET /rest/v2/users` - You will be able to retrieve the available resource of each accounts. The resource could be a device, webpage, layout,or server health monitoring graph.

If it is a device, the Id should match one of the Ids in the response of `GET /rest/v2/devices`
If it is a webpage, the Id should match one of the Ids in the response of  `GET /rest/v2/layouts`
If it is a layout, the Id should match one of the Ids in the response of `GET /rest/v2/webPages`
If it is a server health monitoring graph, the Id should match one of the Ids in the response of  `GET /rest/v2/servers`

Now, we have all the information that is required for creating the mapping of resources and users. 


### The output of the script
You can create your preffered pressenation or format of the result. In this script, we creata a JSON as the output. The sample output can be seen in the [ResourceAndUserMapping.json](ResourceAndUserMapping.json)


## Authors

**Network Optix**

## License
This project is licensed under the [Mozilla Public License, v. 2.0](
http://mozilla.org/MPL/2.0/) - see the [LICENSE.md]() file for details.
