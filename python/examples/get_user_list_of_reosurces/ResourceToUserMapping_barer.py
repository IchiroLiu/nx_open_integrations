#!/usr/bin/python3

import requests
from pprint import pprint
import urllib3
import json
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


'''
It is required and mandatory to use the local account for this one.
The user should be the administrator role or local admin.
'''

USERNAME = 'admin'  # local account username
PASSWORD = 'Admin12345'  # local account password
LOCAL_URL = 'https://127.0.0.1:7001'  # https://<server_ip>:<sever_port>


'''
This is the main class for the request.
It contains the function members to grab the resource and generate the mapping of the user and resource.
Also, the output is defined as a JSON so it can be utilized for different presnetation.
'''
class AllowList:

  def __init__(self, auth_handler):
    self.auth_handler = auth_handler


  def getDeviceList(self,method_header):
    
    deviceList={}
    devices = self.auth_handler.request_api(LOCAL_URL, f'/rest/v2/devices', 'GET', verify=False,headers=method_header)
    for device in devices:
      deviceList[device["id"]] = device["name"]

    return deviceList

  def getLayoutList(self,method_header):
    
    layoutList={}
    layouts = self.auth_handler.request_api(LOCAL_URL, f'/rest/v2/layouts', 'GET', verify=False,headers=method_header)
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

  def getWebPageList(self,method_header):
    
    webPageList={}
    webPages = self.auth_handler.request_api(LOCAL_URL, f'/rest/v2/webPages', 'GET', verify=False,headers=method_header)
    for webPage in webPages:
      webPageList[webPage["id"]] = webPage["name"]
    
    return webPageList  

  def getServerList(self,method_header):
    
    serverList={}
    servers = self.auth_handler.request_api(LOCAL_URL, f'/rest/v2/servers', 'GET', verify=False,headers=method_header)
    for server in servers:
      serverList[server["id"]] = server["name"]
    
    return serverList 

  def getResourceFromLayoutJson(self, json_list, key):

    values = []
    for item in json_list:
        if key in item:
            values.append(item[key])
    return values

  def getAccessbleResourceByRole(self,method_header,roleId):
    
    roles = self.auth_handler.request_api(LOCAL_URL, f'/rest/v2/userRoles', 'GET', verify=False,headers=method_header)
    resource = "accessibleResources"
    
    for role in roles:
      if resource in role and role["id"] == roleId :
        return role["accessibleResources"]
 
  def extractResourcesFromLayout(self,layoutId, deviceList, webPageList, layoutList, serverList, method_header):
    
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

  def mergeAvailableResource(self,is_admin, userId, resourceList,method_header):

    availableResourceList = {"device":[],"layout":[],"webPages":[],"serverHealth":[]}
    
    layoutList = self.getLayoutList(method_header)
    deviceList = self.getDeviceList(method_header)
    webPageList = self.getWebPageList(method_header)
    serverList = self.getServerList(method_header)

    
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
        if resource in layoutList.keys() and not availableResourceList["layout"] and resource != "resource" and resource !="parentId":
          availableResourceList["layout"].append(resource)
          availableResourceList.update(self.extractResourcesFromLayout(resource, deviceList, webPageList, layoutList, serverList, method_header))

      #Append Device
      for resource in resourceList:
        if resource in deviceList.keys():
          #print(deviceList[resource])
          availableResourceList["device"].append(resource)

      #Append webPage
      webPageList = self.getWebPageList(method_header)
      for resource in resourceList:
        if resource in webPageList.keys():
          availableResourceList["webPages"].append(resource)

      #Append serverHealth
      serverList = self.getServerList(method_header)
      for resource in resourceList:
        if resource in serverList.keys() and not availableResourceList["serverHealth"]:
          availableResourceList["serverHealth"].append(resource)

    return availableResourceList

  def generateAccessbleResourceListByUser(self,method_header):
    
    users = self.auth_handler.request_api(LOCAL_URL, f'/rest/v2/users', 'GET', verify=False,headers=method_header)
    resource = "accessibleResources"
    role = "userRoleId"
    permission = "GlobalAdminPermission"

    accessbleResourceListByUser = {}

    for user in users:
      is_admin = False
      if role in user:
        #in a role
        availableResourceByRole = self.getAccessbleResourceByRole(method_header,user[role])
        accessbleResourceListByUser[user["name"]] = self.mergeAvailableResource(is_admin,"none",availableResourceByRole,method_header)
      elif permission in user["permissions"]:
        #administrator/owner
        is_admin = True
        accessbleResourceListByUser[user["name"]] = self.mergeAvailableResource(is_admin,user["id"],[],method_header)
      elif resource not in user:
        #no resource
        accessbleResourceListByUser[user["name"]] = ""
      else:
        availableResourceByUser = user["accessibleResources"]
        accessbleResourceListByUser[user["name"]] = self.mergeAvailableResource(is_admin,"none",availableResourceByUser,method_header)

    return accessbleResourceListByUser

  def generateResourceToUserMappingById(self,method_header):

    UserToResourceMapping = self.generateAccessbleResourceListByUser(method_header)
    ResourceToUserMapping = {"device":{},"layout":{},"webPages":{},"serverHealth":{}}    
    for key, values in UserToResourceMapping.items():
      for value in values:
        for resource in UserToResourceMapping[key][value]:
          if resource not in ResourceToUserMapping[value]:
            ResourceToUserMapping[value][resource] = [key]
          else:
            ResourceToUserMapping[value][resource].append(key)

    ResourceToUserMapping = self.generateResourceToUserMappingWithName(ResourceToUserMapping,method_header)
 
    return ResourceToUserMapping

  def generateResourceToUserMappingWithName(self,ResourceToUserMapping, method_header):

    return self.insertNameIntoMapping(ResourceToUserMapping,method_header)

  def insertNameIntoMapping(self, ResourceToUserMapping, method_header):

    layoutList = self.getLayoutList(method_header)
    deviceList = self.getDeviceList(method_header)
    webPageList = self.getWebPageList(method_header)
    serverList = self.getServerList(method_header)
    
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
It is using the local bearer token authentication, for Nx Witness v5.1, recommedned authentication option
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
      if "type" not in api_response :
          return True
      elif api_response['type'] == 'cloud':
          return False
      else:
          return True

  def create_payload(self):
      payload = {
          'username': USERNAME,
          'password': PASSWORD,
          'setCookie': False
      }
      return payload


  def is_expired(self, api_response):
      if int(api_response['expiresInS']) < 1:
          return True
      else:
          return False


  def create_header(self, bearer_token):
      header = {"Authorization": f"Bearer {bearer_token}"}
      return header


  def tokenPreparation(self):

    cloud_state = self.request_api(LOCAL_URL, f'/rest/v2/login/users/{USERNAME}', 'GET', verify=False)
    if not self.is_local_user(cloud_state):
        print(USERNAME + ' is not a local user.')
        exit(1)

    payload = self.create_payload()
    primary_session = self.request_api(LOCAL_URL, '/rest/v2/login/sessions', 'POST', verify=False, json=payload)
    primary_token = primary_session['token']

    secondary_session = self.request_api(LOCAL_URL, '/rest/v2/login/sessions', 'POST', verify=False, json=payload)
    secondary_token = secondary_session['token']

    primary_token_info = self.request_api(LOCAL_URL, f'/rest/v2/login/sessions/{primary_token}', 'GET', verify=False)
    if self.is_expired(primary_token_info):
        print('Expired token')
        exit(1)

    secondary_token_info = self.request_api(LOCAL_URL, f'/rest/v2/login/sessions/{secondary_token}', 'GET', verify=False)
    if self.is_expired(secondary_token_info):
        print('Expired token')
        exit(1)

    return {"primary_token":primary_token,"secondary_token":secondary_token}


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

    tokens=auth_handler.tokenPreparation()
    get_method_header = auth_handler.create_header(tokens["primary_token"])

    json_string = allowlist.generateResourceToUserMappingById(get_method_header)
    d = generateJsonDump(json_string)

    delete_method_header = auth_handler.create_header(tokens["secondary_token"])
    auth_handler.request_api(LOCAL_URL, f'/rest/v2/login/sessions/{tokens["secondary_token"]}', 'DELETE', verify=False, headers=delete_method_header)

    del allowlist
    del auth_handler

if __name__ == '__main__':
    main()