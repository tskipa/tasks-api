# REST API with Json-Server

API is using json-server with JWT authentication. Cloned from https://github.com/techiediaries/fake-api-jwt-json-server

## Run with JWT:

```bash
$ npm i
$ npm start
```

## Run without JWT:

```bash
$ npm i
$ npm run server
```

## How to post/get data?

Login by sending a POST request to

```
POST http://localhost:3000/api/auth/login
```

with the email and password object. The response will contain

```
{
   "access_token": "<ACCESS_TOKEN>"
}
```

You should send this token with any request to the protected endpoints

```
$ curl 'http://localhost:3000/tasks' -H 'Authorization: Bearer <ACCESS_TOKEN>'
```
