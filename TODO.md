# ignore this file - this is where the mess is

# TODO
# allow command line usage (output to json, console and dict)

# MOCK OUT UNIT TESTS INSTEAD OF DOING MX LOOKUP!

# OTHER RULES
# upper case name if it's included is weird
# if single word person name 'MADDONNA' then no trust
# what is a good name and email address??
# max trust firstname.lastname@companyname.com
# firstinitiallastname@companyname.com

# MOCK OUT MX RECORD REPONSE FROM GMAIL!

#have 1 actual end-to-end test

https://github.com/adam-p/markdown-here/wiki/Markdown-Cheatsheet
https://guides.github.com/features/mastering-markdown/


# practical aim, to decide based on some workflow if it's worth doing
# extra validation of a user, ie. mobile txt etc.
# or whether or not to email them a welcome email or something else etc. etc.


http://www.joewein.net/spam/spam-freemailer.htm
http://www.hubspot.com/list-of-free-email-providers




https://www.quora.com/Is-there-a-way-to-check-if-an-e-mail-address-is-valid-without-e-mailing-it

https://www.emailhippo.com/en-US/verify-email-address/api/a


https://gist.github.com/tbrianjones/5992856



I've been in this business for a long while, and I've built a little step-by-step guide for how to achieve proper email validation without negatively effecting the UX, and I am going to divulge it here:

Syntax Validation: The most obvious part, people - however - know least about. There's more to email syntax validation than the simple PHP RegEx rule you're using. There's the IETF Standards (all the RFCs), but you'll also have to look at ISP-specific syntax checking, quoted words, domain literals, non-ASCII domains, etc.
Disposable & Free Emails: Next, before you use any server side code to check the given email address, it's recommended to check whether or not you're dealing with disposable emails (e.g. mailinator.com) or free emails (Gmail, Yahoo!, etc.) and act accordingly.
Obvious Typos: Now is the time to check for obvious misspellings and typos. (e.g. user@gnail.com would be corrected to user@gmail.com)
DNS validation, including MC record(s) lookup: Verify the DNS MX-Records for the given domain. 
SMTP connection, catch-all check: Now for the meaty part, but also the most risky. Validating email addresses by establishing and then aborting an SMTP connection to the given mail server is still the only way to really find out if a mailbox actually exists. However, if executed in the false way, you will - really quickly - be blacklisted and considered a spammer.




# be cool to be able to pull and update the latest data sets



#' be cool to have a metric based on regex, and have an assigned metric of 0.25 if the regex passes
# have a set of core validation  metrics
# be able to have the metric compairable even if there's 3 rules vs 30 rules 'normalised metric'