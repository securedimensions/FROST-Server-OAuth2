# FROST-Server-OAuth2 Plugin 
This repository contains an OAuth2 / OpenID Connect authentication plugin for [FROST-Server](https://github.com/FraunhoferIOSB/FROST-Server) to be used in combination with the [STAplus](https://github.com/securedimensions/FROST-Server-PLUS) plugin.

The plugin supports OAuth2 Bearer Token as specified in [RFC 6749, §7.1](https://datatracker.ietf.org/doc/html/rfc6749#section-1.4).

This plugin is tested with the Authorization Server [AUTHENIX](https://www.authenix.eu). 

This plugin applies the `sub` value from the OAuth2 TokenInfo response as the `REMOTE_USER`. Technically, the plugin creates a FROST-Server `PrincipalExtended` and adds the entire response from the TokenInfo and UserInfo to the context:

````
PrincipalExtended.name = sub
PrincipalExtended['TokenInfo'] = <response from TokenInfo>
PrincipalExtended['UserInfo'] = <response from UserInfo>
````

The result from the TokenInfo and UserInfo is cached in separate self-expiring ConcurrentHashMap instances. The cache timeout can be configured via `oauth.cacheExpires` with a default of 60 seconds.

## Deployment for existing FROST-Server
The deployment of the OAuth2 plugin requires a working deployment of the FROST-Server.

### Build the OAuth2 plugin
This repository builds with the FROST-Server 2.8.x.

Use `git clone https://github.com/securedimensions/FROST-Server-OAuth2.git` to download the sources.

Then `cd FROST-Server-OAuth2` and use command `mvn install` to produce the JAR file `FROST-Server-2.8.1-SNAPSHOT.Plugin.OAuth2-1.0.1.jar`. Make sure you copy the JAR-file to the appropriate FROST-Server directory.

## Deployment with FROST-Server
Use `git clone -b v2.8.x https://github.com/FraunhoferIOSB/FROST-Server.git FROST-Server-v2.8.x` to create the FROST-Server directory structure.

Then cd `FROST-Server-v2.8.x` and `git clone -b FROST-Server-v2.8.x https://github.com/securedimensions/FROST-Server-OAuth2.git FROST-Server.Auth.OAuth2`.

Add the `OAuth2` plugin to the `FROST-Server-v2.8.x/pom.xml`.

```xml
    <modules>
        <module>FROST-Server.MQTTP</module>
        <module>FROST-Server.HTTP</module>
        <module>FROST-Server.HTTP.Common</module>
        <module>FROST-Server.MQTT</module>
        <module>FROST-Server.MQTT.Moquette</module>
        <module>FROST-Server.Core.Model</module>
        <module>FROST-Server.Core</module>
        <module>FROST-Server.SQLjooq</module>
        <module>FROST-Server.Auth.Basic</module>
        <module>FROST-Server.Auth.Keycloak</module>
        <module>FROST-Server.Auth.OAuth2</module>
        <module>FROST-Server.Util</module>
        <module>Plugins</module>
        <module>Tools</module>
        <module>FROST-Server.Tests</module>
    </modules>
```

Then follow the [FROST-Server documentation](https://fraunhoferiosb.github.io/FROST-Server/deployment/architecture-packages.html) applicable to your deployment strategy.  

## Settings
You can enable this plugin in FROST-Server and configure the behavior by modifying the FROST-Server `context.xml` file.

### Activate the plugin
The plugin is activated by adding the `auth.provider` parameter to the file `context.xml`:

```xml
<Parameter override="false" name="auth.provider" value="de.securedimensions.frostserver.auth.oauth2.OAuth2AuthProvider" description="The java class used to configure authentication/authorisation."/>
```

The realm for the Authentication challenge can be configured via 
```xml
<Parameter override="false" name="auth.realmName" value="FROST-Server-STAplus" />
```

### Authorization Behavior
This plugin can be configured to make authentication optional for HTTP GET which enables anonymous read. To activate anonymous read, please add the following parameter to `context.xml`:

```xml
<Parameter override="false" name="auth.allowAnonymousRead" value="true" />
```

The plugin can also be configured to undertake authentication only (so no authorization on roles is enforced) by adding the following parameter to `context.xml`:

```xml
<Parameter override="false" name="auth.authenticateOnly" value="true" />
```

To enforce simple role based authorization, it is possible to provide the role required for read, create, update and delete. Also, the admin role can be configured this way:

```xml
    <Parameter override="false" name="auth.role.read" value="..." />
    <Parameter override="false" name="auth.role.create" value="..." />
    <Parameter override="false" name="auth.role.update" value="..." />
    <Parameter override="false" name="auth.role.delete" value="..." />
    <Parameter override="false" name="auth.role.admin" value="..." />
```

### Configure the user identifier that gets admin role
Please add the `auth.adminUid` to the configuration. If using AUTHENIX for authentication, the REMOTE_USER is identified by a UUID.

```xml
    <Parameter override="false" name="auth.adminUid" value="<user identifier>" />
```

### Configure the Authorization Server
The following configuration reflects the use of AUTHENIX.  

```xml
    <Parameter override="false" name="auth.oauth.introspectionUrl" value="https://www.authenix.eu/oauth/tokeninfo" />
    <Parameter override="false" name="auth.oauth.userinfoUrl" value="https://www.authenix.eu/openid/userinfo" />
    <Parameter override="false" name="auth.oauth.scope" value="openid" />
    <Parameter override="false" name="auth.oauth.clientId" value="<client_id>" />
    <Parameter override="false" name="auth.oauth.clientSecret" value="<client_secret>" />
```
The `client_id` and `client_secret` can be obtained from registering the plugin as a `Service` with [AUTHENIX register app](https://www.authenix.eu/users/registerapp).

The `auth.oauth.cacheExpires` parameter allows to configure the timeout for the token and user info cache:

```xml
    <Parameter override="false" name="auth.oauth.cacheExpires" value="60" />
```

### Configure local storage of Users
To configure access rights per user, the following configuration options support the creation of users that are identified via this OAuth2 plugin:

Use the boolean parameter `auth.registerUserLocally` to store user's in a database table. Defaults to `false`.

Use the string parameter `auth.userTable` to configure the database table name. Defaults to `USERS`.

Use the string parameter `auth.usernameColumn` to configure the column name that stores the user's identifier (`REMOTE_USER`). Defaults to `USER_NAME`.
