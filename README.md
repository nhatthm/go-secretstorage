# Secret Storage

[![GitHub Releases](https://img.shields.io/github/v/release/nhatthm/go-secretstorage)](https://github.com/nhatthm/go-secretstorage/releases/latest)
[![Build Status](https://github.com/nhatthm/go-secretstorage/actions/workflows/test.yaml/badge.svg)](https://github.com/nhatthm/go-secretstorage/actions/workflows/test.yaml)
[![codecov](https://codecov.io/gh/nhatthm/go-secretstorage/branch/master/graph/badge.svg?token=eTdAgDE2vR)](https://codecov.io/gh/nhatthm/go-secretstorage)
[![Go Report Card](https://goreportcard.com/badge/go.nhat.io/secretstorage)](https://goreportcard.com/report/go.nhat.io/secretstorage)
[![GoDevDoc](https://img.shields.io/badge/dev-doc-00ADD8?logo=go)](https://pkg.go.dev/go.nhat.io/secretstorage)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/donate/?hosted_button_id=PJZSGJN57TDJY)

A library for storing and retrieving secrets.

## Prerequisites

- `Go >= 1.23`

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

If this project help you reduce time to develop, you can give me a cup of coffee :)

### Paypal donation

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/donate/?hosted_button_id=PJZSGJN57TDJY)

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;or scan this

<img src="https://user-images.githubusercontent.com/1154587/113494222-ad8cb200-94e6-11eb-9ef3-eb883ada222a.png" width="147px" />
