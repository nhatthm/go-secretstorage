# Secret Storage

[![GitHub Releases](https://img.shields.io/github/v/release/nhatthm/go-secretstorage)](https://github.com/nhatthm/go-secretstorage/releases/latest)
[![Build Status](https://github.com/nhatthm/go-secretstorage/actions/workflows/test.yaml/badge.svg)](https://github.com/nhatthm/go-secretstorage/actions/workflows/test.yaml)
[![codecov](https://codecov.io/gh/nhatthm/go-secretstorage/branch/master/graph/badge.svg?token=eTdAgDE2vR)](https://codecov.io/gh/nhatthm/go-secretstorage)
[![GoDevDoc](https://img.shields.io/badge/dev-doc-00ADD8?logo=go)](https://pkg.go.dev/go.nhat.io/secretstorage)
[![Donate](https://img.shields.io/badge/%20-Donate-%20?style=flat&logo=githubsponsors&color=E5E4E2)](http://donate.nhat.me)

A library for storing and retrieving secrets.

## Prerequisites

- `Go >= 1.25`

## Install

```bash
go get go.nhat.io/secretstorage
```

## Usage

```go
package main

import (
    "fmt"

    "go.nhat.io/secretstorage"
)

func main() {
    ss := secretstorage.NewKeyringStorage[string]()

    err := ss.Set("service", "key", "value")
    if err != nil {
        panic(err)
    }

    value, err := ss.Get("service", "key")
    if err != nil {
        panic(err)
    }

    fmt.Println(value)
}
```

## Donation

If this project saved you some development time, buy me a cup of coffee :)

[![donate](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](http://donate.nhat.me)

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;or scan this

<img src="https://github.com/nhatthm/donate.nhat.me/blob/master/images/qr_sponsor.png" width="147px" />

[<sub><sup>[table of contents]</sup></sub>](#table-of-contents)
