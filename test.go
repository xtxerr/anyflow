package main

import "fmt"
import "strconv"

func main() {

	a := 2048

	b := strconv.Itoa(a)

	fmt.Println("len of b:=strconv.Itoa(a) is ", len(b))

}
