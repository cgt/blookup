# blookup

DNS blacklist/whitelist lookup tool.

## Installation
```
go get cgt.name/pkg/blookup
```

## Usage
```blookup 203.0.113.82```

This command will look up the IP address 203.0.113.82 in various
blacklists/whitelists and print hits to stdout.
The IP's PTR record will also be resolved.

See `-help` for additional options.

## License
Copyright Christoffer G. Thomsen 2016

Distributed under the Boost Software License, Version 1.0.

(See accompanying file LICENSE or copy at
http://www.boost.org/LICENSE_1_0.txt)

reverseaddr.go contains code from the Go standard library which is subject to
a BSD 3-clause license. See reverseaddr.go for details.
