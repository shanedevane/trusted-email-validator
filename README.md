# Trusted Email Validator
  
[![Build Status](https://travis-ci.org/shanedevane/trusted-email-validator.svg?branch=master)](https://travis-ci.org/shanedevane/trusted-email-validator)
 
Checks an email address using Regex, MX Data and Trust Rules to assign a Trust Rating value to an email address.

```python
TrustedEmailValidator.is_trusted('_ShaneDevaneX990_@hotmail.com')
```


## Purpose
To be able to change a program workflow based on how 'trustworthy' and email address might be and to store the trust data as json into a data store.

Possible use cases:
- Deciding if further email or sms validation is required to validate an email address
- Deciding if manual intervention is required for accepting an application/order coming from an email address
- Deciding if the email address is an organisation vs. a free email provider
   
# Usage

#### Quick Usage ####
By default TrustedEmailValidator does a MX lookup
```python
TrustedEmailValidator.is_valid('firstname@companyname.com')
```

```python
decision = TrustedEmailValidator('firstname@companyname.com')

if decision:
    print(decision)
    print(decision.data)
    
>>> firstname@companyname.com is trusted
>>> 
```


## Regex Validation ##

Common regex validation for email addresses (handles ' in usernames and .museum TLD).

## Domain Classification ##

Common comparison of domain name via data files to discover if they are free email accounts or not.

## MX Lookup ##

Common DNS Mail Server LookUp to make sure there are mail servers available for the email address.

## Trust Rules##

The trust rules incorporated into this project are kept at a minimum level so to provide a wider scope of uses.
It is recommended to review them to understand if the business logic is valid for your context.

## What it doesn't do ##

This does not try to initiate a connection to the users mail server to see if the email username exists. This is an
unreliable metric as many mail servers by default do not respond to it. ie. Exchange.

# Install

python setup.py install


## References

**awesome work on classifying free emails**
https://github.com/willwhite/freemail

**good concept**
https://github.com/uploadcare/intercom-rank

