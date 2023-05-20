import requests
from pprint import pprint
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
import time
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


USERNAME = 'admin'  # local account username
PASSWORD = 'Admin12345'  # local account password
LOCAL_URL = 'https://127.0.0.1:7001'  # https://<server_ip>:<sever_port>
API_URI = '/api/moduleInformation?allModules=true'  # API request URI
API_METHOD = 'GET'  # API request method

'''
It is required and mandatory to use the local account for this one.
The user should be the administrator role or local admin.
'''
class AllowList:

  def __init__(self, auth_handler):
    self.auth_handler = auth_handler


  def getDeviceList(self):
    
    deviceList={}
    devices = self.auth_handler.request_api(LOCAL_URL, f'/rest/v2/devices', 'GET', auth=HTTPDigestAuth(USERNAME, PASSWORD),verify=False)
    for device in devices:
      deviceList[device["id"]] = device["name"]

    return deviceList

  def getLayoutList(self):
    
    layoutList={}
    layouts = self.auth_handler.request_api(LOCAL_URL, f'/rest/v2/layouts', 'GET', auth=HTTPDigestAuth(USERNAME, PASSWORD),verify=False)
    for layout in layouts:
      layoutList[layout["id"]] = layout["name"]
      
      if "items" in layout:
        layoutList["resource"] = self.getResourceFromLayoutJson(layout["items"],"resourceId")
      else:
        layoutList["resource"] = []
          
      if "parentId" in layout:
        layoutList["parentId"] = layout["parentId"]
      else:
        layoutList["parentId"] = ""
      
    return layoutList  

  def getWebPageList(self):
    
    webPageList={}
    webPages = self.auth_handler.request_api(LOCAL_URL, f'/rest/v2/webPages', 'GET', auth=HTTPDigestAuth(USERNAME, PASSWORD),verify=False)
    for webPage in webPages:
      webPageList[webPage["id"]] = webPage["name"]
    
    return webPageList  

  def getServerList(self):
    
    serverList={}
    servers = self.auth_handler.request_api(LOCAL_URL, f'/rest/v2/servers', 'GET', auth=HTTPDigestAuth(USERNAME, PASSWORD),verify=False)
    for server in servers:
      serverList[server["id"]] = server["name"]
    
    return serverList 

  def getResourceFromLayoutJson(self, json_list, key):

    values = []
    for item in json_list:
        if key in item:
            values.append(item[key])
    return values

  def getAccessbleResourceByRole(self,roleId):
    
    roles = self.auth_handler.request_api(LOCAL_URL, f'/rest/v2/userRoles', 'GET', auth=HTTPDigestAuth(USERNAME, PASSWORD),verify=False)
    resource = "accessibleResources"
    
    for role in roles:
      if resource in role and role["id"] == roleId :
        return role["accessibleResources"]
 
  def extractResourcesFromLayout(self,layoutId, deviceList, webPageList, layoutList, serverList):
    
    availableResourceList = {"device":[],"layout":[],"webPages":[],"serverHealth":[]}

    if layoutId in layoutList.keys():
        availableResourceList["layout"].append(layoutId)
        for resource in layoutList["resource"]:
          if resource in deviceList.keys():
            availableResourceList["device"].append(resource)
          elif resource in webPageList.keys():
            availableResourceList["webPages"].append(resource)
          elif resource in serverList.keys():
            availableResourceList["serverHealth"].append(resource)

    return availableResourceList

  def mergeAvailableResource(self,is_admin, userId, resourceList):

    availableResourceList = {"device":[],"layout":[],"webPages":[],"serverHealth":[]}
    
    layoutList = self.getLayoutList()
    deviceList = self.getDeviceList()
    webPageList = self.getWebPageList()
    serverList = self.getServerList()

    
    if is_admin :
      #Appen All
      for key in layoutList.keys():
        if layoutList["parentId"] == "" and key != "resource" and key !="parentId":
            availableResourceList["layout"].append(key)
        elif userId in layoutList["parentId"] and key != "resource" and key !="parentId":
            availableResourceList["layout"].append(key)
      availableResourceList["device"]=list(deviceList.keys())    
      availableResourceList["webPages"]=list(webPageList.keys())
      availableResourceList["serverHealth"]=list(serverList.keys())


    else:
    
      #Append Layout
      for resource in resourceList:
        if resource in layoutList.keys() and not availableResourceList["layout"] and resource != "resource" :
          availableResourceList["layout"].append(resource)
          availableResourceList.update(self.extractResourcesFromLayout(resource, deviceList, webPageList, layoutList, serverList))

      #Append Device
      for resource in resourceList:
        if resource in deviceList.keys():
          #print(deviceList[resource])
          availableResourceList["device"].append(resource)

      #Append webPage
      webPageList = self.getWebPageList()
      for resource in resourceList:
        if resource in webPageList.keys():
          availableResourceList["webPages"].append(resource)

      #Append serverHealth
      serverList = self.getServerList()
      for resource in resourceList:
        if resource in serverList.keys() and not availableResourceList["serverHealth"]:
          print(serverList[resource])
          availableResourceList["serverHealth"].append(resource)

    return availableResourceList

  def generateAccessbleResourceListByUser(self):
    
    users = self.auth_handler.request_api(LOCAL_URL, f'/rest/v2/users', 'GET', auth=HTTPDigestAuth(USERNAME, PASSWORD),verify=False)
    resource = "accessibleResources"
    role = "userRoleId"
    permission = "GlobalAdminPermission"

    accessbleResourceListByUser = {}

    for user in users:
      is_admin = False
      if role in user:
        #in a role
        availableResourceByRole = self.getAccessbleResourceByRole(user[role])
        accessbleResourceListByUser[user["name"]] = self.mergeAvailableResource(is_admin,"none",availableResourceByRole)
      elif permission in user["permissions"]:
        #administrator/owner
        is_admin = True
        accessbleResourceListByUser[user["name"]] = self.mergeAvailableResource(is_admin,user["id"],[])
      elif resource not in user:
        #no resource
        accessbleResourceListByUser[user["name"]] = ""
      else:
        availableResourceByUser = user["accessibleResources"]
        accessbleResourceListByUser[user["name"]] = self.mergeAvailableResource(is_admin,"none",availableResourceByUser)

    return accessbleResourceListByUser

  def generateResourceToUserMappingById(self):

    UserToResourceMapping = self.generateAccessbleResourceListByUser()
    ResourceToUserMapping = {"device":{},"layout":{},"webPages":{},"serverHealth":{}}    
    for key, values in UserToResourceMapping.items():
      for value in values:
        for resource in UserToResourceMapping[key][value]:
          if resource not in ResourceToUserMapping[value]:
            ResourceToUserMapping[value][resource] = [key]
          else:
            ResourceToUserMapping[value][resource].append(key)

    ResourceToUserMapping = self.generateResourceToUserMappingWithName(ResourceToUserMapping)
 
    return ResourceToUserMapping

  def generateResourceToUserMappingWithName(self,ResourceToUserMapping):

    return self.insertNameIntoMapping(ResourceToUserMapping)

  def insertNameIntoMapping(self, ResourceToUserMapping):

    layoutList = self.getLayoutList()
    deviceList = self.getDeviceList()
    webPageList = self.getWebPageList()
    serverList = self.getServerList()
    
    for item in ResourceToUserMapping["layout"]:
      name = layoutList[item]
      users = ResourceToUserMapping["layout"][item]
      ResourceToUserMapping["layout"][item]=[name,users]
      #print(ResourceToUserMapping["layout"][item])
    
    for item in ResourceToUserMapping["device"]:
      name = deviceList[item]
      users = ResourceToUserMapping["device"][item]
      ResourceToUserMapping["device"][item]=[name,users]

    for item in ResourceToUserMapping["webPages"]:
      name = webPageList[item]
      users = ResourceToUserMapping["webPages"][item]
      ResourceToUserMapping["webPages"][item]=[name,users]

    for item in ResourceToUserMapping["serverHealth"]:
      name = serverList[item]
      users = ResourceToUserMapping["serverHealth"][item]
      ResourceToUserMapping["serverHealth"][item]=[name,users]

    return ResourceToUserMapping

'''
This is the main class for the authentication.
It is using the local http digest authentication, for Nx Witness v5.1, you will need to enable the digest authentication for each user.
Ref : https://support.networkoptix.com/hc/en-us/articles/7724435803415-How-to-Enable-Digest-Authentication-for-3rd-Party-Applications
'''
class Auth:

  def check_status(self, response, verbose):
      if response.status_code == requests.codes.ok:
          if verbose:
              print("Request successful\n{0}".format(response.text))
          return True
      print(response.url + " Request error {0}\n{1}".format(response.status_code, response.text))
      return False


  def request_api(self, url, uri, method, **kwargs):
      server_url = f'{url}{uri}'
      response = requests.request(
          method,
          server_url,
          **kwargs
      )
      if not self.check_status(response, False):
          exit(1)
      if response.headers.get('Content-Type') == 'application/json':
          return response.json()
      else:
          return response.content

  def is_local_user(self, api_response):
      if api_response['type'] == 'cloud':
          return False
      else:
          return True


#Construct the dictionary for output the JSON
def rebuildListWithAttr(resourcelist):
  
  rebuildList = []
  for key,value in resourcelist.items():
    rebuildList.append({"resourceId":key, "name":value[0], "users":value[1]})
  
  return rebuildList


def generateJsonDump(ResourceAndUserMapping, output=True):

  json_string = {}
  for key,value in ResourceAndUserMapping.items():

     json_string[key] = rebuildListWithAttr(value)
  
  if output : 
    with open("ResourceAndUserMapping.json", "w") as f:
      json.dump(json_string, f)
  
  return json.dumps(json_string)    


#Main Entry point
def main():

    auth_handler = Auth()
    allowlist = AllowList(auth_handler)

    json_string = allowlist.generateResourceToUserMappingById()
    d = generateJsonDump(json_string)

    del allowlist
    del auth_handler

if __name__ == '__main__':
    main()