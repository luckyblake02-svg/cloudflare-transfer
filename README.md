# cloudflare-transfer
This is a script that will transfer your domain(s) from DNSimple (with CSC registrar) to cloudflare. This does not change the registrar. Just DNSimple -> Cloudflare. It does this by grabbing the zone files for each domain in a given list, changes the syntax of certain records, then splitting URL records into a separate file.
After this, the domain is added to cloudflare, then an API call to CSC is made to change the name servers to the cloudflare-assigned servers. Then, page rules are created for the domain for each URL record.
