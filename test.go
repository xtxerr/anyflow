package main

import "fmt"

//var slice = make([]string, 100)
var slice [100]string

func main() {
	slice[2] = "foo"
	slice[10] = "foo"

	for a, b := range slice {

		fmt.Println(a, "=>", b)

	}
}
