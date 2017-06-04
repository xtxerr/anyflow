package main

import "fmt"

func main() {

	a := []string{"foo", "bar", "sup"}

	fmt.Println(a[1])

	b := a[2:]

	fmt.Println(b[0])

}
