# Trusted Email Validator
Validates an email address using regex and smtp mx record checking and assigns a level of 'trust'

# About

Yet another email validator. The goal is to accomplish if an email address could be thought of as being 
'trustworthy' with the output being an object that can be serialised and saved into a data store.

This uses some of the common approaches for email validation that already exist but brings in additional
checking via a 'trust' metric that takes the approach of business logic rules that would result in further
trusting an email address. 

## Regex Validation ##

Common regex validation

## Domain Classification ##

Common comparison of domain name via data files

## MX Lookup ##

Common DNS Mail Server LookUp

## Trust Rules##

The trust rules incorporated into this project are kept at a minimum level so to provide a wider scope of uses.
It is recommended to review them to understand the logic.





## References

###### awesome work on classifying free emails
https://github.com/willwhite/freemail

###### good concept
https://github.com/uploadcare/intercom-rank

