# Trusted Email Validator
Validates an email address using regex and smtp mx record checking and assigns a level of 'trust'

# About

Yet another email validator. The goal is to accomplish if an email address could be thought of as being 
'trustworthy' with the output being an object that can be serialised and saved into a data store.

This uses some of the common approaches for email validation that already exist but brings in additional
checking via a 'trust' metric that takes the approach of business logic rules that would result in further
trusting an email address.

# Aim

The purpose is to be able to change the workflow of an application based on the 'trustworthiness' of the email 
address.

Use cases:
- Deciding if further email or sms validation is required to validate the user
- Deciding if manual intervention is required for accepting an application/order
- Deciding if the email address is an organisation
 
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

# Travis

https://travis-ci.org/shanedevane/trusted-email-validator/builds


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

## References

**awesome work on classifying free emails**
https://github.com/willwhite/freemail

**good concept**
https://github.com/uploadcare/intercom-rank

