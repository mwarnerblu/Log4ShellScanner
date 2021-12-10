# Log4ShellScanner
Scans and catches callbacks of systems that are impacted by Log4J Log4Shell vulnerability across specific headers.

*Very Beta Warning!* :)

![Alt text](https://raw.githubusercontent.com/mwarnerblu/Log4ShellScanner/main/extras/log4shellscanner_output.png "Log4Shell Scanner Output")

In an effort to simplify the annoying effort of figuring out what actually has vulnerable log4j, I put together a scanner which attempts to pollute X-Api-Version, User-Agent, and Authentication headers. In my testing I'm able to get back vulnerable servers however this likely need additional expansion as new methods of injection are realized.

# Usage
If building locally nothing fancy is required, I used go 1.16 but it's a fairly straightforward script. Otherwise theres are only 4 params required for the run:

`-SourceIP` - Source of the requests and the IP you want to have called back to
`-SourcePort` - Port you want this script to listen on locally
`-DestCIDR` - CIDR you want scanned (bigger will take longer)
`-DestPort` - Port that you want to target for scanning

Otherwise it's a simple run as you can see from the output above:

```
./log4shell -SourceIP 192.168.10.130 -SourcePort 8081 -DestCIDR 192.168.10.0/24 -DestPort 8080
```

# Known Limitations
As this was thrown together for internal testing and validation there's a few limitations still! 

* Only goes over HTTP right now, HTTPS can be easily added in the future
* Does not allow a variety of ports
* Could be better threaded 
* Doesn't handle exit gracefully and just waits for callbacks
